/*
- PROJECT : VIREO
- FILE    : test_connection_pool_ownership.c
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 真实连接转移、租约复用、总容量和 fd 生命周期测试
- -- 公开 loop 回调在途保护及本模块消费型 IO 边界注入
 */
#define _GNU_SOURCE
#include "net/connection_pool_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned failures;
static unsigned groups;
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

typedef struct socket_fixture {
    vireo_connection_t *owner;
    int fd;
    int peer;
} socket_fixture_t;

static socket_fixture_t make_connection(size_t read_capacity, size_t write_capacity)
{
    int pair[2];
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
    socket_fixture_t fixture = {NULL, pair[0], pair[1]};
    vireo_connection_options_t options = {
        read_capacity, write_capacity, read_capacity + write_capacity
    };
    int fd_owner = pair[0];
    REQUIRE(vireo_connection_create(&options, &fd_owner, &fixture.owner, NULL) == VIREO_OK);
    CHECK(fd_owner == -1);
    return fixture;
}

static vireo_connection_pool_t *make_pool(size_t capacity, size_t buffer_budget)
{
    vireo_connection_pool_t *pool = NULL;
    vireo_connection_pool_options_t const options = {capacity, 65536, buffer_budget};
    REQUIRE(vireo_connection_pool_create(&options, &pool, NULL) == VIREO_OK);
    return pool;
}

static vireo_connection_pool_info_t inspect(vireo_connection_pool_t *pool)
{
    vireo_connection_pool_info_t info;
    REQUIRE(vireo_connection_pool_inspect(pool, &info) == VIREO_OK);
    return info;
}

static void cleanup(socket_fixture_t *fixture)
{
    if (fixture->owner != NULL) {
        CHECK(vireo_connection_destroy(&fixture->owner, NULL) == VIREO_OK);
    }
    CHECK(close(fixture->peer) == 0);
}

static void check_closed(int fd)
{
    errno = 0;
    CHECK(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
}

static int lease_equal(vireo_connection_pool_lease_t a, vireo_connection_pool_lease_t b)
{
    return a.pool_id == b.pool_id && a.slot_index == b.slot_index && a.generation == b.generation;
}

static unsigned fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    REQUIRE(directory != NULL);
    unsigned count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (entry->d_name[0] != '.') {
            ++count;
        }
    }
    REQUIRE(closedir(directory) == 0);
    return count;
}

static void test_option_budget(void)
{
    ++groups;
    vireo_connection_pool_t *pool = NULL;
    vireo_connection_pool_options_t options = {1, 65536, 0};
    vireo_connection_pool_error_t error;
    errno = E2BIG;
    CHECK(vireo_connection_pool_create(&options, &pool, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == E2BIG && pool == NULL && error.stage == VIREO_CONNECTION_POOL_STAGE_NONE);
    options.max_buffer_bytes = VIREO_CONNECTION_POOL_MAX_BUFFER_MEMORY + 1;
    CHECK(vireo_connection_pool_create(&options, &pool, &error) == VIREO_RESULT_RANGE);
    CHECK(errno == E2BIG && pool == NULL);
    options.max_buffer_bytes = 1;
    REQUIRE(vireo_connection_pool_create(&options, &pool, NULL) == VIREO_OK);
    vireo_connection_pool_info_t info = inspect(pool);
    CHECK(info.buffer_capacity_bytes == 0 && info.max_buffer_bytes == 1);
    CHECK(vireo_connection_pool_destroy(&pool, NULL) == VIREO_OK && errno == E2BIG);
}

/* 收纳不把半关闭、已有接收字节或待发字节当成必须清空的“新对象”。 */
static void test_transfer_preserves_data(void)
{
    ++groups;
    socket_fixture_t fixture = make_connection(8, 8);
    REQUIRE(send(fixture.peer, "abc", 3, MSG_NOSIGNAL) == 3);
    REQUIRE(shutdown(fixture.peer, SHUT_WR) == 0);
    vireo_connection_receive_budget_t const budget = {8, 4};
    vireo_connection_receive_info_t received;
    REQUIRE(vireo_connection_receive(fixture.owner, &budget, &received, NULL) == VIREO_OK);
    CHECK(received.received_bytes == 3 &&
          received.stop_reason == VIREO_CONNECTION_RECEIVE_STOP_EOF);
    REQUIRE(vireo_connection_write_enqueue(fixture.owner, (uint8_t const *)"reply", 5, NULL) ==
            VIREO_OK);
    vireo_connection_t *original = fixture.owner;
    vireo_connection_pool_t *pool = make_pool(2, 32);
    vireo_connection_pool_lease_t lease;
    vireo_connection_pool_operation_error_t error;
    errno = E2BIG;
    REQUIRE(vireo_connection_pool_adopt(pool, &fixture.owner, &lease, &error) == VIREO_OK);
    CHECK(errno == E2BIG && fixture.owner == NULL);
    CHECK(lease.pool_id != 0 && lease.generation != 0 && lease.slot_index < 2);
    CHECK(error.stage == VIREO_CONNECTION_POOL_OPERATION_NONE);
    CHECK(error.connection_error.stage == VIREO_CONNECTION_STAGE_NONE);
    vireo_connection_t *borrowed = NULL;
    REQUIRE(vireo_connection_pool_lookup(pool, lease, &borrowed) == VIREO_OK);
    CHECK(errno == E2BIG && borrowed == original);
    vireo_connection_info_t info;
    REQUIRE(vireo_connection_inspect(borrowed, &info) == VIREO_OK);
    CHECK(info.read_eof && info.read_buffer.readable_size == 3 &&
          info.write_buffer.readable_size == 5);
    uint8_t const *bytes;
    size_t size;
    REQUIRE(vireo_connection_read_peek(borrowed, &bytes, &size) == VIREO_OK);
    CHECK(size == 3 && memcmp(bytes, "abc", 3) == 0);
    vireo_connection_pool_info_t pinfo = inspect(pool);
    CHECK(pinfo.leased_slots == 1 && pinfo.available_slots == 1 &&
          pinfo.buffer_capacity_bytes == 16);
    REQUIRE(vireo_connection_pool_release(pool, &lease, &error) == VIREO_OK);
    CHECK(errno == E2BIG && lease_equal(lease, (vireo_connection_pool_lease_t){0, 0, 0}));
    check_closed(fixture.fd);
    cleanup(&fixture);
    CHECK(vireo_connection_pool_destroy(&pool, NULL) == VIREO_OK);
}

static void test_full_pool(void)
{
    ++groups;
    vireo_connection_pool_t *pool = make_pool(1, 64);
    socket_fixture_t first = make_connection(8, 8);
    socket_fixture_t second = make_connection(8, 8);
    vireo_connection_pool_lease_t current;
    REQUIRE(vireo_connection_pool_adopt(pool, &first.owner, &current, NULL) == VIREO_OK);
    vireo_connection_pool_lease_t out;
    memset(&out, 0xa5, sizeof(out));
    unsigned char before[sizeof(out)];
    memcpy(before, &out, sizeof(out));
    vireo_connection_t *original = second.owner;
    vireo_connection_pool_operation_error_t error;
    errno = E2BIG;
    CHECK(vireo_connection_pool_adopt(pool, &second.owner, &out, &error) == VIREO_RESULT_BUSY);
    CHECK(errno == E2BIG && second.owner == original && memcmp(before, &out, sizeof(out)) == 0);
    CHECK(error.stage == VIREO_CONNECTION_POOL_OPERATION_ACQUIRE_SLOT);
    CHECK(inspect(pool).leased_slots == 1 && inspect(pool).buffer_capacity_bytes == 16);
    REQUIRE(vireo_connection_pool_release(pool, &current, NULL) == VIREO_OK);
    REQUIRE(vireo_connection_pool_adopt(pool, &second.owner, &out, NULL) == VIREO_OK);
    REQUIRE(vireo_connection_pool_release(pool, &out, NULL) == VIREO_OK);
    cleanup(&first);
    cleanup(&second);
    CHECK(vireo_connection_pool_destroy(&pool, NULL) == VIREO_OK);
}

static void test_aggregate_budget(void)
{
    ++groups;
    vireo_connection_pool_t *pool = make_pool(3, 32);
    socket_fixture_t a = make_connection(8, 8);
    socket_fixture_t b = make_connection(8, 8);
    socket_fixture_t c = make_connection(4, 4);
    vireo_connection_pool_lease_t la;
    vireo_connection_pool_lease_t lb;
    vireo_connection_pool_lease_t lc = {123, 456, 789};
    REQUIRE(vireo_connection_pool_adopt(pool, &a.owner, &la, NULL) == VIREO_OK);
    REQUIRE(vireo_connection_pool_adopt(pool, &b.owner, &lb, NULL) == VIREO_OK);
    CHECK(inspect(pool).buffer_capacity_bytes == 32);
    vireo_connection_t *original = c.owner;
    errno = E2BIG;
    CHECK(vireo_connection_pool_adopt(pool, &c.owner, &lc, NULL) == VIREO_RESULT_BUSY);
    CHECK(errno == E2BIG && c.owner == original && lc.pool_id == 123 && lc.generation == 789);
    REQUIRE(vireo_connection_pool_release(pool, &la, NULL) == VIREO_OK);
    CHECK(inspect(pool).buffer_capacity_bytes == 16);
    REQUIRE(vireo_connection_pool_adopt(pool, &c.owner, &lc, NULL) == VIREO_OK);
    CHECK(inspect(pool).buffer_capacity_bytes == 24);
    REQUIRE(vireo_connection_pool_release(pool, &lb, NULL) == VIREO_OK);
    REQUIRE(vireo_connection_pool_release(pool, &lc, NULL) == VIREO_OK);
    CHECK(inspect(pool).buffer_capacity_bytes == 0);
    cleanup(&a); cleanup(&b); cleanup(&c);
    CHECK(vireo_connection_pool_destroy(&pool, NULL) == VIREO_OK);
}

static void test_single_too_large(void)
{
    ++groups;
    vireo_connection_pool_t *pool = make_pool(2, 15);
    socket_fixture_t fixture = make_connection(8, 8);
    vireo_connection_pool_lease_t lease = {123, 456, 789};
    vireo_connection_t *original = fixture.owner;
    errno = E2BIG;
    CHECK(vireo_connection_pool_adopt(pool, &fixture.owner, &lease, NULL) == VIREO_RESULT_RANGE);
    CHECK(errno == E2BIG && fixture.owner == original && lease.pool_id == 123);
    CHECK(inspect(pool).leased_slots == 0 && inspect(pool).buffer_capacity_bytes == 0);
    cleanup(&fixture);
    CHECK(vireo_connection_pool_destroy(&pool, NULL) == VIREO_OK);
}

static void test_lease_validation(void)
{
    ++groups;
    vireo_connection_pool_t *pool = make_pool(2, 32);
    vireo_connection_pool_t *other = make_pool(2, 32);
    socket_fixture_t fixture = make_connection(8, 8);
    vireo_connection_pool_lease_t current;
    REQUIRE(vireo_connection_pool_adopt(pool, &fixture.owner, &current, NULL) == VIREO_OK);
    vireo_connection_t *borrowed;
    REQUIRE(vireo_connection_pool_lookup(pool, current, &borrowed) == VIREO_OK);
    vireo_connection_t *original = borrowed;
    vireo_connection_pool_lease_t invalid[] = {
        {0, 0, 0}, {0, 1, 1}, {current.pool_id, current.slot_index, 0},
        {current.pool_id, SIZE_MAX, current.generation},
        {current.pool_id, current.slot_index, current.generation + 1}
    };
    vireo_result_t const expected[] = {
        VIREO_RESULT_NOT_FOUND, VIREO_RESULT_INVALID_ARGUMENT, VIREO_RESULT_INVALID_ARGUMENT,
        VIREO_RESULT_RANGE, VIREO_RESULT_NOT_FOUND
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        unsigned char before[sizeof(invalid[i])];
        memcpy(before, &invalid[i], sizeof(before));
        errno = E2BIG;
        CHECK(vireo_connection_pool_lookup(pool, invalid[i], &borrowed) == expected[i]);
        CHECK(borrowed == original && errno == E2BIG);
        CHECK(vireo_connection_pool_release(pool, &invalid[i], NULL) == expected[i]);
        CHECK(memcmp(before, &invalid[i], sizeof(before)) == 0 && errno == E2BIG);
    }
    vireo_connection_pool_lease_t copy = current;
    CHECK(vireo_connection_pool_lookup(other, current, &borrowed) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_pool_release(other, &copy, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(lease_equal(copy, current) && borrowed == original);
    REQUIRE(vireo_connection_pool_release(pool, &current, NULL) == VIREO_OK);
    CHECK(vireo_connection_pool_release(pool, &copy, NULL) == VIREO_RESULT_NOT_FOUND);
    borrowed = NULL;
    CHECK(vireo_connection_pool_lookup(pool, copy, &borrowed) == VIREO_RESULT_NOT_FOUND);
    CHECK(borrowed == NULL);
    CHECK(vireo_connection_pool_release(pool, &current, NULL) == VIREO_RESULT_NOT_FOUND);
    cleanup(&fixture);
    CHECK(vireo_connection_pool_destroy(&pool, NULL) == VIREO_OK);
    CHECK(vireo_connection_pool_destroy(&other, NULL) == VIREO_OK);
}

/* 单槽重复复用必须拒绝旧租约；只比较有效指针，不在消费后读取旧别名。 */
static void test_reuse(void)
{
    ++groups;
    vireo_connection_pool_t *pool = make_pool(1, 16);
    vireo_connection_pool_lease_t previous = {0, 0, 0};
    for (unsigned i = 0; i < 128; ++i) {
        socket_fixture_t fixture = make_connection(8, 8);
        vireo_connection_pool_lease_t current;
        REQUIRE(vireo_connection_pool_adopt(pool, &fixture.owner, &current, NULL) == VIREO_OK);
        CHECK(current.slot_index == 0 && current.generation > previous.generation);
        vireo_connection_t *borrowed = NULL;
        CHECK(vireo_connection_pool_lookup(pool, previous, &borrowed) == VIREO_RESULT_NOT_FOUND);
        CHECK(borrowed == NULL);
        if (i != 0) {
            CHECK(vireo_connection_pool_release(pool, &previous, NULL) == VIREO_RESULT_NOT_FOUND);
        }
        REQUIRE(vireo_connection_pool_lookup(pool, current, &borrowed) == VIREO_OK);
        previous = current;
        REQUIRE(vireo_connection_pool_release(pool, &current, NULL) == VIREO_OK);
        CHECK(inspect(pool).leased_slots == 0 && inspect(pool).buffer_capacity_bytes == 0);
        check_closed(fixture.fd);
        cleanup(&fixture);
    }
    CHECK(vireo_connection_pool_destroy(&pool, NULL) == VIREO_OK);
}

typedef struct dependency_fixture {
    unsigned inspections;
    unsigned destroys;
    vireo_result_t inspect_result;
    int corrupt_capacity;
    int busy;
    int close_errno;
} dependency_fixture_t;

static vireo_result_t injected_inspect(void *context, vireo_connection_t const *connection,
                                      vireo_connection_info_t *out)
{
    dependency_fixture_t *f = context;
    ++f->inspections;
    errno = ENOTTY;
    if (f->inspect_result != VIREO_OK) {
        return f->inspect_result;
    }
    vireo_result_t result = vireo_connection_inspect(connection, out);
    REQUIRE(result == VIREO_OK);
    if (f->corrupt_capacity == 1) {
        ++out->buffer_capacity_bytes;
    } else if (f->corrupt_capacity == 2) {
        out->read_buffer.capacity = SIZE_MAX;
    }
    return result;
}

/* IO 注入前先真实销毁连接，遵守依赖消费合同；不是内核 close 故障复现。 */
static vireo_result_t injected_destroy(void *context, vireo_connection_t **owner,
                                      vireo_connection_error_t *error)
{
    dependency_fixture_t *f = context;
    ++f->destroys;
    errno = ENOTTY;
    if (f->busy != 0) {
        *error = (vireo_connection_error_t){VIREO_CONNECTION_STAGE_NONE, 0};
        return VIREO_RESULT_BUSY;
    }
    vireo_result_t result = vireo_connection_destroy(owner, error);
    REQUIRE(result == VIREO_OK);
    if (f->close_errno != 0) {
        *error = (vireo_connection_error_t){VIREO_CONNECTION_STAGE_CLOSE_SOCKET, f->close_errno};
        return VIREO_RESULT_IO;
    }
    return result;
}

static vireo_connection_pool_t *make_injected_pool(dependency_fixture_t *fixture)
{
    vireo_connection_pool_t *pool = NULL;
    vireo_connection_pool_options_t const options = {2, 65536, 16};
    vireo_connection_pool_connection_ops_t const ops = {
        fixture, injected_inspect, injected_destroy
    };
    REQUIRE(vireo_connection_pool_create_with_connection_ops(&options, &ops, &pool, NULL) ==
            VIREO_OK);
    return pool;
}

static void test_consumed_io(void)
{
    ++groups;
    int const close_errors[] = {EINTR, EIO};
    for (size_t i = 0; i < sizeof(close_errors) / sizeof(close_errors[0]); ++i) {
        dependency_fixture_t f = {0};
        f.close_errno = close_errors[i];
        vireo_connection_pool_t *pool = make_injected_pool(&f);
        socket_fixture_t fixture = make_connection(8, 8);
        vireo_connection_pool_lease_t lease;
        REQUIRE(vireo_connection_pool_adopt(pool, &fixture.owner, &lease, NULL) == VIREO_OK);
        vireo_connection_pool_lease_t copy = lease;
        vireo_connection_pool_operation_error_t error;
        errno = E2BIG;
        CHECK(vireo_connection_pool_release(pool, &lease, &error) == VIREO_RESULT_IO);
        CHECK(errno == E2BIG && f.destroys == 1);
        CHECK(error.stage == VIREO_CONNECTION_POOL_OPERATION_DESTROY_CONNECTION);
        CHECK(error.connection_error.stage == VIREO_CONNECTION_STAGE_CLOSE_SOCKET &&
              error.connection_error.system_errno == close_errors[i]);
        CHECK(lease_equal(lease, (vireo_connection_pool_lease_t){0, 0, 0}));
        CHECK(inspect(pool).buffer_capacity_bytes == 0 && inspect(pool).leased_slots == 0);
        CHECK(vireo_connection_pool_release(pool, &copy, NULL) == VIREO_RESULT_NOT_FOUND);
        CHECK(f.destroys == 1);
        check_closed(fixture.fd);
        cleanup(&fixture);
        f.close_errno = 0;
        fixture = make_connection(8, 8);
        REQUIRE(vireo_connection_pool_adopt(pool, &fixture.owner, &lease, NULL) == VIREO_OK);
        REQUIRE(vireo_connection_pool_release(pool, &lease, NULL) == VIREO_OK);
        CHECK(f.destroys == 2);
        cleanup(&fixture);
        CHECK(vireo_connection_pool_destroy(&pool, NULL) == VIREO_OK);
    }
}

static void test_dependency_rejections(void)
{
    ++groups;
    dependency_fixture_t f = {0};
    vireo_connection_pool_t *pool = make_injected_pool(&f);
    socket_fixture_t fixture = make_connection(8, 8);
    vireo_connection_t *original = fixture.owner;
    vireo_connection_pool_lease_t lease = {123, 456, 789};
    vireo_connection_pool_operation_error_t error;
    f.inspect_result = VIREO_RESULT_INVALID_ARGUMENT;
    errno = E2BIG;
    CHECK(vireo_connection_pool_adopt(pool, &fixture.owner, &lease, &error) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(error.stage == VIREO_CONNECTION_POOL_OPERATION_INSPECT_CONNECTION && errno == E2BIG);
    f.inspect_result = VIREO_OK;
    f.corrupt_capacity = 1;
    CHECK(vireo_connection_pool_adopt(pool, &fixture.owner, &lease, &error) ==
          VIREO_RESULT_INTERNAL);
    f.corrupt_capacity = 2;
    CHECK(vireo_connection_pool_adopt(pool, &fixture.owner, &lease, &error) ==
          VIREO_RESULT_OVERFLOW);
    CHECK(errno == E2BIG && fixture.owner == original && lease.pool_id == 123);
    CHECK(inspect(pool).leased_slots == 0);
    f.corrupt_capacity = 0;
    REQUIRE(vireo_connection_pool_adopt(pool, &fixture.owner, &lease, NULL) == VIREO_OK);
    vireo_connection_pool_lease_t copy = lease;
    f.busy = 1;
    CHECK(vireo_connection_pool_release(pool, &lease, &error) == VIREO_RESULT_BUSY);
    CHECK(errno == E2BIG && lease_equal(lease, copy) && f.destroys == 1);
    CHECK(inspect(pool).buffer_capacity_bytes == 16);
    vireo_connection_t *borrowed = NULL;
    REQUIRE(vireo_connection_pool_lookup(pool, lease, &borrowed) == VIREO_OK);
    CHECK(borrowed == original);
    f.busy = 0;
    REQUIRE(vireo_connection_pool_release(pool, &lease, &error) == VIREO_OK);
    CHECK(error.stage == VIREO_CONNECTION_POOL_OPERATION_NONE &&
          error.connection_error.system_errno == 0 && errno == E2BIG);
    cleanup(&fixture);
    CHECK(vireo_connection_pool_destroy(&pool, NULL) == VIREO_OK);
}

static void unused_callback(vireo_connection_t *connection, uint32_t events, void *context)
{
    (void)connection; (void)events; (void)context;
    CHECK(0);
}

static vireo_event_loop_t *make_loop(void)
{
    vireo_event_loop_options_t const options = {4, 65536, 4};
    vireo_event_loop_t *loop = NULL;
    REQUIRE(vireo_event_loop_create(&options, &loop, NULL) == VIREO_OK);
    return loop;
}

static void test_bound_lifecycle(void)
{
    ++groups;
    vireo_connection_pool_t *pool = make_pool(1, 16);
    vireo_event_loop_t *loop = make_loop();
    socket_fixture_t fixture = make_connection(8, 8);
    REQUIRE(vireo_connection_attach(fixture.owner, loop, VIREO_EPOLL_INTEREST_READ,
                                   unused_callback, NULL, NULL) == VIREO_OK);
    vireo_connection_pool_lease_t lease = {123, 456, 789};
    vireo_connection_t *original = fixture.owner;
    errno = E2BIG;
    CHECK(vireo_connection_pool_adopt(pool, &fixture.owner, &lease, NULL) == VIREO_RESULT_BUSY);
    CHECK(errno == E2BIG && fixture.owner == original && lease.pool_id == 123);
    REQUIRE(vireo_connection_detach(fixture.owner, NULL) == VIREO_OK);
    REQUIRE(vireo_connection_pool_adopt(pool, &fixture.owner, &lease, NULL) == VIREO_OK);
    vireo_connection_t *borrowed;
    REQUIRE(vireo_connection_pool_lookup(pool, lease, &borrowed) == VIREO_OK);
    REQUIRE(vireo_connection_attach(borrowed, loop, VIREO_EPOLL_INTEREST_READ,
                                   unused_callback, NULL, NULL) == VIREO_OK);
    REQUIRE(vireo_connection_request_close(borrowed, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
                                          VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) ==
            VIREO_OK);
    vireo_connection_pool_lease_t copy = lease;
    CHECK(vireo_connection_pool_release(pool, &lease, NULL) == VIREO_RESULT_BUSY);
    CHECK(errno == E2BIG && lease_equal(copy, lease) && inspect(pool).leased_slots == 1);
    REQUIRE(vireo_connection_detach(borrowed, NULL) == VIREO_OK);
    REQUIRE(vireo_connection_pool_release(pool, &lease, NULL) == VIREO_OK);
    cleanup(&fixture);
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    CHECK(vireo_connection_pool_destroy(&pool, NULL) == VIREO_OK);
}

typedef struct callback_fixture {
    vireo_connection_pool_t *pool;
    vireo_connection_pool_lease_t lease;
    vireo_connection_t **external_owner;
    unsigned calls;
} callback_fixture_t;

static void detach_callback(vireo_connection_t *connection, uint32_t events, void *context)
{
    callback_fixture_t *f = context;
    ++f->calls;
    CHECK((events & VIREO_EPOLL_EVENT_READ) != 0);
    REQUIRE(vireo_connection_detach(connection, NULL) == VIREO_OK);
    errno = E2BIG;
    if (f->external_owner != NULL) {
        vireo_connection_pool_lease_t out = {123, 456, 789};
        CHECK(vireo_connection_pool_adopt(f->pool, f->external_owner, &out, NULL) ==
              VIREO_RESULT_BUSY);
        CHECK(*f->external_owner == connection && out.pool_id == 123);
    } else {
        vireo_connection_pool_lease_t before = f->lease;
        CHECK(vireo_connection_pool_release(f->pool, &f->lease, NULL) == VIREO_RESULT_BUSY);
        CHECK(lease_equal(before, f->lease) && inspect(f->pool).leased_slots == 1);
        vireo_connection_t *borrowed = NULL;
        CHECK(vireo_connection_pool_lookup(f->pool, f->lease, &borrowed) == VIREO_OK);
        CHECK(borrowed == connection);
    }
    CHECK(errno == E2BIG);
}

static void test_callback_in_flight(void)
{
    ++groups;
    for (unsigned external = 0; external <= 1; ++external) {
        vireo_connection_pool_t *pool = make_pool(1, 16);
        vireo_event_loop_t *loop = make_loop();
        socket_fixture_t fixture = make_connection(8, 8);
        callback_fixture_t f = {pool, {0, 0, 0}, external != 0 ? &fixture.owner : NULL, 0};
        vireo_connection_t *connection = fixture.owner;
        if (external == 0) {
            REQUIRE(vireo_connection_pool_adopt(pool, &fixture.owner, &f.lease, NULL) == VIREO_OK);
        }
        REQUIRE(vireo_connection_attach(connection, loop, VIREO_EPOLL_INTEREST_READ,
                                       detach_callback, &f, NULL) == VIREO_OK);
        REQUIRE(send(fixture.peer, "x", 1, MSG_NOSIGNAL) == 1);
        vireo_event_loop_run_info_t info;
        REQUIRE(vireo_event_loop_run_once(loop, 0, &info, NULL) == VIREO_OK);
        CHECK(f.calls == 1 && info.dispatched_count == 1);
        if (external != 0) {
            REQUIRE(vireo_connection_pool_adopt(pool, &fixture.owner, &f.lease, NULL) == VIREO_OK);
        }
        REQUIRE(vireo_connection_pool_release(pool, &f.lease, NULL) == VIREO_OK);
        cleanup(&fixture);
        CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
        CHECK(vireo_connection_pool_destroy(&pool, NULL) == VIREO_OK);
    }
}

static void test_closing_lifecycle(void)
{
    ++groups;
    vireo_connection_pool_t *pool = make_pool(1, 16);
    socket_fixture_t fixture = make_connection(8, 8);
    REQUIRE(vireo_connection_request_close(fixture.owner, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
                                          VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) ==
            VIREO_OK);
    vireo_connection_pool_lease_t lease = {123, 456, 789};
    CHECK(vireo_connection_pool_adopt(pool, &fixture.owner, &lease, NULL) == VIREO_RESULT_BUSY);
    cleanup(&fixture);
    fixture = make_connection(8, 8);
    REQUIRE(vireo_connection_pool_adopt(pool, &fixture.owner, &lease, NULL) == VIREO_OK);
    vireo_connection_t *borrowed;
    REQUIRE(vireo_connection_pool_lookup(pool, lease, &borrowed) == VIREO_OK);
    REQUIRE(vireo_connection_write_enqueue(borrowed, (uint8_t const *)"queued", 6, NULL) ==
            VIREO_OK);
    REQUIRE(vireo_connection_request_close(borrowed, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
                                          VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) ==
            VIREO_OK);
    vireo_connection_info_t info;
    REQUIRE(vireo_connection_inspect(borrowed, &info) == VIREO_OK);
    CHECK(info.close_state == VIREO_CONNECTION_CLOSE_DRAINING);
    REQUIRE(vireo_connection_pool_release(pool, &lease, NULL) == VIREO_OK);
    check_closed(fixture.fd);
    cleanup(&fixture);
    CHECK(vireo_connection_pool_destroy(&pool, NULL) == VIREO_OK);
}

static void test_nonempty_destroy(void)
{
    ++groups;
    vireo_connection_pool_t *pool = make_pool(1, 16);
    vireo_connection_pool_t *original = pool;
    socket_fixture_t fixture = make_connection(8, 8);
    vireo_connection_pool_lease_t lease;
    REQUIRE(vireo_connection_pool_adopt(pool, &fixture.owner, &lease, NULL) == VIREO_OK);
    errno = E2BIG;
    CHECK(vireo_connection_pool_destroy(&pool, NULL) == VIREO_RESULT_BUSY);
    CHECK(errno == E2BIG && pool == original && inspect(pool).buffer_capacity_bytes == 16);
    vireo_connection_t *borrowed = NULL;
    CHECK(vireo_connection_pool_lookup(pool, lease, &borrowed) == VIREO_OK && borrowed != NULL);
    REQUIRE(vireo_connection_pool_release(pool, &lease, NULL) == VIREO_OK);
    cleanup(&fixture);
    CHECK(vireo_connection_pool_destroy(&pool, NULL) == VIREO_OK);
}

static void test_invalid_arguments(void)
{
    ++groups;
    vireo_connection_pool_t *pool = make_pool(1, 16);
    socket_fixture_t fixture = make_connection(8, 8);
    vireo_connection_pool_lease_t lease = {123, 456, 789};
    vireo_connection_t *empty = NULL;
    vireo_connection_t *original = fixture.owner;
    vireo_connection_pool_operation_error_t error;
    errno = E2BIG;
    CHECK(vireo_connection_pool_adopt(NULL, &fixture.owner, &lease, &error) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_pool_adopt(pool, NULL, &lease, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_pool_adopt(pool, &empty, &lease, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_pool_adopt(pool, &fixture.owner, NULL, NULL) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_pool_lookup(NULL, lease, &empty) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_pool_lookup(pool, lease, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_pool_release(NULL, &lease, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_pool_release(pool, NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == E2BIG && fixture.owner == original && empty == NULL && lease.pool_id == 123);
    CHECK(error.stage == VIREO_CONNECTION_POOL_OPERATION_NONE &&
          error.connection_error.system_errno == 0);
    vireo_connection_pool_connection_ops_t ops = {0};
    vireo_connection_pool_t *out = NULL;
    vireo_connection_pool_options_t const options = {1, 65536, 16};
    CHECK(vireo_connection_pool_create_with_connection_ops(&options, &ops, &out, NULL) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(out == NULL && errno == E2BIG);
    cleanup(&fixture);
    CHECK(vireo_connection_pool_destroy(&pool, NULL) == VIREO_OK);
}

static void test_independent_pools(void)
{
    ++groups;
    vireo_connection_pool_t *first = make_pool(1, 16);
    vireo_connection_pool_t *second = make_pool(1, 16);
    socket_fixture_t a = make_connection(8, 8);
    socket_fixture_t b = make_connection(8, 8);
    vireo_connection_pool_lease_t la;
    vireo_connection_pool_lease_t lb;
    REQUIRE(vireo_connection_pool_adopt(first, &a.owner, &la, NULL) == VIREO_OK);
    REQUIRE(vireo_connection_pool_adopt(second, &b.owner, &lb, NULL) == VIREO_OK);
    CHECK(la.pool_id != lb.pool_id);
    vireo_connection_t *borrowed;
    REQUIRE(vireo_connection_pool_lookup(second, lb, &borrowed) == VIREO_OK);
    REQUIRE(vireo_connection_pool_release(first, &la, NULL) == VIREO_OK);
    CHECK(vireo_connection_pool_destroy(&first, NULL) == VIREO_OK);
    vireo_connection_t *again = NULL;
    REQUIRE(vireo_connection_pool_lookup(second, lb, &again) == VIREO_OK);
    CHECK(again == borrowed && inspect(second).buffer_capacity_bytes == 16);
    REQUIRE(vireo_connection_pool_release(second, &lb, NULL) == VIREO_OK);
    cleanup(&a); cleanup(&b);
    CHECK(vireo_connection_pool_destroy(&second, NULL) == VIREO_OK);
}

int main(void)
{
    unsigned const baseline = fd_count();
    test_option_budget();
    test_transfer_preserves_data();
    test_full_pool();
    test_aggregate_budget();
    test_single_too_large();
    test_lease_validation();
    test_reuse();
    test_consumed_io();
    test_dependency_rejections();
    test_bound_lifecycle();
    test_callback_in_flight();
    test_closing_lifecycle();
    test_nonempty_destroy();
    test_invalid_arguments();
    test_independent_pools();
    CHECK(fd_count() == baseline);
    printf("connection pool ownership: %u groups, %u failures; fd baseline %u restored\n",
           groups, failures, baseline);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
