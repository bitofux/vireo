/*
- PROJECT : VIREO
- FILE    : test_acceptor_integration.c
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 公开监听接入、客户 fd/connection/pool 所有权交接与有界字节收发
- -- 真实预算/槽位/注册拒绝、在途保护、独立清理与租约复用
 */
#define _GNU_SOURCE
#include <vireo/net/acceptor.h>
#include <vireo/net/connection_pool.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>

static unsigned failures;
static unsigned groups;
static unsigned unix_names;
static unsigned reused_fds;
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

typedef enum mode {
    PIPELINE,
    CREATE_RANGE,
    POOL_SLOTS,
    POOL_BUDGET,
    POOL_RANGE,
    LOOP_FULL,
    KEEP,
    STOP_IN_CALLBACK
} integration_mode_t;

typedef struct fixture fixture_t;
typedef struct client_slot {
    fixture_t *fixture;
    vireo_connection_pool_lease_t lease;
    vireo_connection_pool_lease_t issued_lease;
    int numeric_fd; /* 仅比较复用/消费后检查；不越过 connection 操作 fd。 */
    size_t received;
    size_t sent;
    unsigned callbacks;
    bool ready_to_release;
} client_slot_t;

struct fixture {
    vireo_acceptor_t *acceptor;
    vireo_event_loop_t *loop;
    vireo_connection_pool_t *pool;
    int numeric_listener;
    int family;
    struct sockaddr_storage address;
    socklen_t address_size;
    integration_mode_t mode;
    size_t pool_capacity;
    size_t expected;
    size_t accepted;
    size_t rejected;
    size_t completed;
    size_t slot_next;
    size_t batch_limit;
    unsigned accept_callbacks;
    uint32_t seen_ids;
    client_slot_t slots[4];
};

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

static bool lease_empty(vireo_connection_pool_lease_t lease)
{
    return lease.pool_id == 0 && lease.slot_index == 0 && lease.generation == 0;
}

static bool lease_equal(vireo_connection_pool_lease_t a, vireo_connection_pool_lease_t b)
{
    return a.pool_id == b.pool_id && a.slot_index == b.slot_index && a.generation == b.generation;
}

static void check_closed(int numeric_fd)
{
    errno = 0;
    CHECK(fcntl(numeric_fd, F_GETFD) == -1 && errno == EBADF);
}

static vireo_connection_t *lookup(fixture_t *f, vireo_connection_pool_lease_t lease)
{
    vireo_connection_t *borrowed = NULL;
    EXPECT(vireo_connection_pool_lookup(f->pool, lease, &borrowed), VIREO_OK);
    REQUIRE(borrowed != NULL);
    return borrowed;
}

static vireo_connection_info_t connection_info(vireo_connection_t *connection)
{
    vireo_connection_info_t info;
    EXPECT(vireo_connection_inspect(connection, &info), VIREO_OK);
    return info;
}

static vireo_connection_pool_info_t pool_info(fixture_t *f)
{
    vireo_connection_pool_info_t info;
    EXPECT(vireo_connection_pool_inspect(f->pool, &info), VIREO_OK);
    CHECK(info.leased_slots + info.available_slots == f->pool_capacity);
    CHECK(info.buffer_capacity_bytes == info.leased_slots * 128);
    return info;
}

static void check_empty_pool(fixture_t *f)
{
    vireo_connection_pool_info_t const info = pool_info(f);
    CHECK(info.leased_slots == 0 && info.available_slots == f->pool_capacity);
    CHECK(info.buffer_capacity_bytes == 0);
}

/* 故意用每轮两个字节预算；字节回显是测试载荷，不是协议 handler。 */
static void client_callback(vireo_connection_t *connection, uint32_t events, void *context)
{
    client_slot_t *slot = context;
    fixture_t *f = slot->fixture;
    CHECK(connection == lookup(f, slot->lease));
    ++slot->callbacks;
    vireo_connection_info_t info = connection_info(connection);
    CHECK(info.loop_attached && info.callback_active);
    if ((events & VIREO_EPOLL_EVENT_READ) != 0) {
        vireo_connection_receive_budget_t const budget = {2, 1};
        vireo_connection_receive_info_t progress;
        EXPECT(vireo_connection_receive(connection, &budget, &progress, NULL), VIREO_OK);
        CHECK(progress.received_bytes <= 2 && progress.recv_calls <= 1);
        slot->received += progress.received_bytes;
        uint8_t const *data = NULL;
        size_t size = 0;
        EXPECT(vireo_connection_read_peek(connection, &data, &size), VIREO_OK);
        CHECK(size <= 4);
        if (size == 4) {
            unsigned const id = data[0];
            REQUIRE(id >= 1 && id <= 8);
            CHECK(data[1] == (uint8_t)(128U + id) && data[2] == 19 && data[3] == 211);
            uint32_t const bit = UINT32_C(1) << (id - 1);
            CHECK((f->seen_ids & bit) == 0);
            f->seen_ids |= bit;
            EXPECT(vireo_connection_write_enqueue(connection, data, size, NULL), VIREO_OK);
            /* enqueue 已复制；成功 consume 结束此只读借用。 */
            EXPECT(vireo_connection_read_consume(connection, size), VIREO_OK);
            EXPECT(vireo_connection_request_close(connection, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
                VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL), VIREO_OK);
            info = connection_info(connection);
            CHECK(info.close_state == VIREO_CONNECTION_CLOSE_DRAINING);
            CHECK(info.loop_interests == VIREO_EPOLL_INTEREST_WRITE);
        }
    }
    if ((events & VIREO_EPOLL_EVENT_WRITE) != 0) {
        vireo_connection_send_budget_t const budget = {2, 1};
        vireo_connection_send_info_t progress;
        EXPECT(vireo_connection_send(connection, &budget, &progress, NULL), VIREO_OK);
        CHECK(progress.sent_bytes <= 2 && progress.send_calls <= 1);
        slot->sent += progress.sent_bytes;
        EXPECT(vireo_connection_close_refresh(connection, NULL), VIREO_OK);
        info = connection_info(connection);
        if (info.close_state == VIREO_CONNECTION_CLOSE_READY) {
            CHECK(slot->received == 4 && slot->sent == 4 && info.write_buffer.readable_size == 0);
            EXPECT(vireo_connection_detach(connection, NULL), VIREO_OK);
            info = connection_info(connection);
            CHECK(!info.loop_attached && info.callback_active);
            vireo_connection_pool_lease_t const original = slot->lease;
            EXPECT(vireo_connection_pool_release(f->pool, &slot->lease, NULL), VIREO_RESULT_BUSY);
            CHECK(lease_equal(slot->lease, original));
            slot->ready_to_release = true;
        }
    }
    CHECK((events & (VIREO_EPOLL_EVENT_ERROR | VIREO_EPOLL_EVENT_HANGUP)) == 0);
}

static void attach_client(fixture_t *f, client_slot_t *slot)
{
    vireo_connection_t *borrowed = lookup(f, slot->lease);
    EXPECT(vireo_connection_attach(borrowed, f->loop, VIREO_EPOLL_INTEREST_READ,
                                   client_callback, slot, NULL), VIREO_OK);
}

/* raw owner/临时 owner/lease 分别收尾，绝不把 lookup 借用当 owner。 */
static void handoff(fixture_t *f, int *fd_owner)
{
    REQUIRE(f->slot_next < 4 && *fd_owner >= 0);
    client_slot_t *slot = &f->slots[f->slot_next++];
    *slot = (client_slot_t){.fixture = f, .numeric_fd = *fd_owner};
    vireo_connection_options_t const options = {64, 64, f->mode == CREATE_RANGE ? 127 : 128};
    vireo_connection_t *owner = NULL;
    vireo_connection_error_t error;
    int const original_fd = *fd_owner;
    errno = E2BIG;
    vireo_result_t const created = vireo_connection_create(&options, fd_owner, &owner, &error);
    CHECK(errno == E2BIG);
    if (f->mode == CREATE_RANGE) {
        CHECK(created == VIREO_RESULT_RANGE && owner == NULL && *fd_owner == original_fd);
        CHECK(error.stage == VIREO_CONNECTION_STAGE_NONE && error.system_errno == 0);
        CHECK(fcntl(*fd_owner, F_GETFD) >= 0);
        CHECK(close(*fd_owner) == 0);
        *fd_owner = -1;
        check_closed(original_fd);
        ++f->rejected;
        return;
    }
    REQUIRE(created == VIREO_OK && owner != NULL && *fd_owner == -1);
    vireo_connection_t *original_owner = owner;
    vireo_connection_pool_lease_t lease = {17, 18, 19};
    vireo_connection_pool_operation_error_t operation;
    errno = E2BIG;
    vireo_result_t const adopted = vireo_connection_pool_adopt(f->pool, &owner, &lease, &operation);
    CHECK(errno == E2BIG);
    if (adopted != VIREO_OK) {
        CHECK(f->mode == POOL_SLOTS || f->mode == POOL_BUDGET || f->mode == POOL_RANGE);
        CHECK(adopted == (f->mode == POOL_RANGE ? VIREO_RESULT_RANGE : VIREO_RESULT_BUSY));
        CHECK(owner == original_owner && lease.pool_id == 17 && lease.slot_index == 18 &&
              lease.generation == 19);
        CHECK(!connection_info(owner).loop_attached);
        EXPECT(vireo_connection_destroy(&owner, NULL), VIREO_OK);
        CHECK(owner == NULL);
        check_closed(original_fd);
        ++f->rejected;
        return;
    }
    CHECK(owner == NULL && !lease_empty(lease));
    slot->lease = lease;
    slot->issued_lease = lease;
    if (f->mode == LOOP_FULL) {
        vireo_connection_loop_error_t loop_error;
        vireo_connection_t *borrowed = lookup(f, lease);
        EXPECT(vireo_connection_attach(borrowed, f->loop, VIREO_EPOLL_INTEREST_READ,
            client_callback, slot, &loop_error), VIREO_RESULT_BUSY);
        CHECK(loop_error.stage == VIREO_CONNECTION_LOOP_STAGE_ATTACH);
        CHECK(loop_error.loop_error.stage == VIREO_EVENT_LOOP_STAGE_NONE);
        CHECK(!connection_info(borrowed).loop_attached);
        EXPECT(vireo_connection_pool_release(f->pool, &slot->lease, NULL), VIREO_OK);
        CHECK(lease_empty(slot->lease));
        check_closed(original_fd);
        ++f->rejected;
    } else if (f->mode == PIPELINE || f->mode == STOP_IN_CALLBACK) {
        attach_client(f, slot);
    }
}

static void accept_callback(vireo_acceptor_t *acceptor, uint32_t events, void *context)
{
    fixture_t *f = context;
    CHECK(acceptor == f->acceptor && (events & VIREO_EPOLL_EVENT_READ) != 0);
    ++f->accept_callbacks;
    vireo_acceptor_info_t state;
    EXPECT(vireo_acceptor_inspect(acceptor, &state), VIREO_OK);
    CHECK(state.loop_attached && state.callback_active && state.read_enabled);
    int owners[2] = {-1, -1};
    vireo_acceptor_accept_budget_t const budget = {f->batch_limit, 3};
    vireo_acceptor_accept_info_t progress;
    EXPECT(vireo_acceptor_accept_batch(acceptor, &budget, owners, 2, &progress, NULL), VIREO_OK);
    CHECK(progress.accepted_count >= 1 && progress.accepted_count <= f->batch_limit);
    CHECK(progress.accept_calls <= 3);
    for (size_t i = 0; i < progress.accepted_count; ++i) {
        CHECK((fcntl(owners[i], F_GETFL) & O_NONBLOCK) != 0);
        CHECK((fcntl(owners[i], F_GETFD) & FD_CLOEXEC) != 0);
        handoff(f, &owners[i]);
        CHECK(owners[i] == -1);
        ++f->accepted;
    }
    for (size_t i = progress.accepted_count; i < 2; ++i) CHECK(owners[i] == -1);
    CHECK(f->accepted <= f->expected);
    if (f->mode == STOP_IN_CALLBACK) {
        EXPECT(vireo_acceptor_detach(acceptor, NULL), VIREO_OK);
        EXPECT(vireo_acceptor_inspect(acceptor, &state), VIREO_OK);
        CHECK(!state.loop_attached && state.callback_active);
        vireo_acceptor_t *original = f->acceptor;
        EXPECT(vireo_acceptor_destroy(&f->acceptor, NULL), VIREO_RESULT_BUSY);
        CHECK(f->acceptor == original);
        EXPECT(vireo_event_loop_request_stop(f->loop, NULL), VIREO_OK);
    } else if (f->accepted == f->expected) {
        EXPECT(vireo_acceptor_set_read_enabled(acceptor, false, NULL), VIREO_OK);
    }
}

static void fixture_init(fixture_t *f, int family, integration_mode_t mode, size_t pool_capacity,
                          size_t pool_budget, size_t registration_capacity)
{
    *f = (fixture_t){.family = family, .mode = mode, .pool_capacity = pool_capacity,
                     .expected = 1, .batch_limit = 2};
    int fd_owner = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    REQUIRE(fd_owner >= 0);
    f->numeric_listener = fd_owner;
    if (family == AF_INET) {
        struct sockaddr_in address = {0};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        REQUIRE(bind(fd_owner, (struct sockaddr const *)&address, (socklen_t)sizeof(address)) == 0);
    } else {
        REQUIRE(family == AF_UNIX);
        struct sockaddr_un address = {0};
        address.sun_family = AF_UNIX;
        int const n = snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1,
                               "vireo-integration-%ld-%u", (long)getpid(), ++unix_names);
        REQUIRE(n > 0 && (size_t)n < sizeof(address.sun_path) - 1);
        REQUIRE(bind(fd_owner, (struct sockaddr const *)&address, (socklen_t)sizeof(address)) == 0);
    }
    REQUIRE(listen(fd_owner, 8) == 0);
    f->address_size = (socklen_t)sizeof(f->address);
    REQUIRE(getsockname(fd_owner, (struct sockaddr *)&f->address, &f->address_size) == 0);
    vireo_acceptor_options_t const options = {4096};
    EXPECT(vireo_acceptor_create(&options, &fd_owner, &f->acceptor, NULL), VIREO_OK);
    REQUIRE(fd_owner == -1 && f->acceptor != NULL);
    vireo_connection_pool_options_t const pool_options = {pool_capacity, 65536, pool_budget};
    EXPECT(vireo_connection_pool_create(&pool_options, &f->pool, NULL), VIREO_OK);
    REQUIRE(f->pool != NULL);
    vireo_event_loop_options_t const loop_options = {8, 65536, registration_capacity};
    EXPECT(vireo_event_loop_create(&loop_options, &f->loop, NULL), VIREO_OK);
    REQUIRE(f->loop != NULL);
    EXPECT(vireo_acceptor_attach(f->acceptor, f->loop, true, accept_callback, f, NULL), VIREO_OK);
}

static int connect_peer(fixture_t const *f, uint8_t id)
{
    int const peer = socket(f->family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(peer >= 0);
    REQUIRE(connect(peer, (struct sockaddr const *)&f->address, f->address_size) == 0);
    uint8_t const bytes[4] = {id, (uint8_t)(128U + id), 19, 211};
    REQUIRE(send(peer, bytes, sizeof(bytes), MSG_NOSIGNAL) == (ssize_t)sizeof(bytes));
    return peer;
}

static vireo_event_loop_run_info_t run_once(fixture_t *f)
{
    vireo_event_loop_run_info_t info;
    EXPECT(vireo_event_loop_run_once(f->loop, 100, &info, NULL), VIREO_OK);
    CHECK(info.ready_count == info.dispatched_count + info.stale_count + info.filtered_count);
    return info;
}

/* 借用在归还前结束；release 之后只使用独立数值副本检查失效。 */
static void release_slot(fixture_t *f, client_slot_t *slot)
{
    vireo_connection_pool_lease_t const previous = slot->lease;
    EXPECT(vireo_connection_pool_release(f->pool, &slot->lease, NULL), VIREO_OK);
    CHECK(lease_empty(slot->lease));
    check_closed(slot->numeric_fd);
    vireo_connection_t *out = NULL;
    EXPECT(vireo_connection_pool_lookup(f->pool, previous, &out), VIREO_RESULT_NOT_FOUND);
    CHECK(out == NULL);
}

static void pump_pipeline(fixture_t *f)
{
    for (unsigned turn = 0; turn < 40 && f->completed < f->expected; ++turn) {
        (void)run_once(f);
        for (size_t i = 0; i < f->slot_next; ++i) {
            client_slot_t *slot = &f->slots[i];
            if (slot->ready_to_release) {
                vireo_connection_info_t const info = connection_info(lookup(f, slot->lease));
                CHECK(!info.callback_active && !info.loop_attached);
                CHECK(info.close_state == VIREO_CONNECTION_CLOSE_READY);
                release_slot(f, slot);
                slot->ready_to_release = false;
                ++f->completed;
            }
        }
    }
    REQUIRE(f->accepted == f->expected && f->completed == f->expected);
    check_empty_pool(f);
}

static void check_response(int peer, uint8_t id)
{
    uint8_t response[4] = {0};
    size_t used = 0;
    while (used < sizeof(response)) {
        struct pollfd ready = {peer, POLLIN, 0};
        REQUIRE(poll(&ready, 1, 1000) == 1);
        ssize_t const n = recv(peer, response + used, sizeof(response) - used, MSG_DONTWAIT);
        REQUIRE(n > 0 && (size_t)n <= sizeof(response) - used);
        used += (size_t)n;
    }
    uint8_t const expected[4] = {id, (uint8_t)(128U + id), 19, 211};
    CHECK(memcmp(response, expected, sizeof(response)) == 0);
}

static void fixture_cleanup(fixture_t *f)
{
    for (size_t i = 0; i < f->slot_next; ++i) {
        if (!lease_empty(f->slots[i].lease)) {
            vireo_connection_t *borrowed = lookup(f, f->slots[i].lease);
            if (connection_info(borrowed).loop_attached) {
                EXPECT(vireo_connection_detach(borrowed, NULL), VIREO_OK);
            }
            release_slot(f, &f->slots[i]);
        }
    }
    check_empty_pool(f);
    if (f->acceptor != NULL) {
        EXPECT(vireo_acceptor_detach(f->acceptor, NULL), VIREO_OK);
        EXPECT(vireo_acceptor_destroy(&f->acceptor, NULL), VIREO_OK);
        check_closed(f->numeric_listener);
    }
    EXPECT(vireo_connection_pool_destroy(&f->pool, NULL), VIREO_OK);
    EXPECT(vireo_event_loop_destroy(&f->loop, NULL), VIREO_OK);
    CHECK(f->acceptor == NULL && f->pool == NULL && f->loop == NULL);
}

static void test_pipeline(int family)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, family, PIPELINE, 3, 384, 4);
    f.expected = 3;
    int peers[3];
    for (unsigned i = 0; i < 3; ++i) peers[i] = connect_peer(&f, (uint8_t)(i + 1));
    vireo_event_loop_run_info_t const first = run_once(&f);
    CHECK(first.ready_count == 1 && first.dispatched_count == 1);
    CHECK(f.accepted == 2 && f.completed == 0 && f.accept_callbacks == 1);
    CHECK(pool_info(&f).leased_slots == 2);
    for (size_t i = 0; i < 2; ++i) CHECK(f.slots[i].callbacks == 0);
    pump_pipeline(&f);
    CHECK(f.accept_callbacks == 2 && f.seen_ids == 7);
    for (unsigned i = 0; i < 3; ++i) {
        check_response(peers[i], (uint8_t)(i + 1));
        CHECK(close(peers[i]) == 0);
    }
    fixture_cleanup(&f);
}

static void test_rejection(integration_mode_t mode)
{
    ++groups;
    unsigned const before = fd_count();
    fixture_t f;
    size_t const capacity = mode == POOL_SLOTS ? 1 : 2;
    size_t const budget = mode == POOL_RANGE ? 127 :
        (mode == POOL_BUDGET || mode == POOL_SLOTS ? 128 : 256);
    fixture_init(&f, AF_INET, mode, capacity, budget, mode == LOOP_FULL ? 1 : 3);
    f.expected = 2;
    int const first = connect_peer(&f, 1);
    int const second = connect_peer(&f, 2);
    CHECK(run_once(&f).dispatched_count == 1 && f.accepted == 2);
    if (mode == POOL_SLOTS || mode == POOL_BUDGET) {
        CHECK(f.rejected == 1);
        vireo_connection_pool_info_t const info = pool_info(&f);
        CHECK(info.leased_slots == 1 && info.buffer_capacity_bytes == 128);
        CHECK(info.available_slots == (mode == POOL_SLOTS ? 0 : 1));
        vireo_connection_pool_t *original_pool = f.pool;
        EXPECT(vireo_connection_pool_destroy(&f.pool, NULL), VIREO_RESULT_BUSY);
        CHECK(f.pool == original_pool);
        release_slot(&f, &f.slots[0]);
    } else {
        CHECK(f.rejected == 2);
    }
    check_empty_pool(&f);
    CHECK(close(first) == 0 && close(second) == 0);
    /* 拒绝清理后，listener 和有限接入能力继续可用。 */
    f.mode = KEEP;
    f.accepted = 0;
    f.expected = 1;
    f.slot_next = 0;
    f.batch_limit = 1;
    EXPECT(vireo_acceptor_set_read_enabled(f.acceptor, true, NULL), VIREO_OK);
    int const next = connect_peer(&f, 3);
    if (mode == POOL_RANGE) {
        /* 相同预算仍不能收纳；先只验证 raw fd 接入和 caller 清理。 */
        EXPECT(vireo_acceptor_set_read_enabled(f.acceptor, false, NULL), VIREO_OK);
        int raw_fd = -1;
        vireo_acceptor_accept_budget_t const limit = {1, 1};
        vireo_acceptor_accept_info_t progress;
        EXPECT(vireo_acceptor_accept_batch(f.acceptor, &limit, &raw_fd, 1, &progress, NULL), VIREO_OK);
        REQUIRE(raw_fd >= 0 && progress.accepted_count == 1);
        CHECK(close(raw_fd) == 0);
    } else {
        CHECK(run_once(&f).dispatched_count == 1 && f.accepted == 1);
        CHECK(pool_info(&f).leased_slots == 1);
        release_slot(&f, &f.slots[0]);
    }
    CHECK(close(next) == 0);
    fixture_cleanup(&f);
    CHECK(fd_count() == before);
}

static void test_listener_client_independence(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_INET, PIPELINE, 1, 128, 2);
    int const peer = connect_peer(&f, 4);
    CHECK(run_once(&f).dispatched_count == 1 && f.accepted == 1);
    EXPECT(vireo_acceptor_detach(f.acceptor, NULL), VIREO_OK);
    EXPECT(vireo_acceptor_destroy(&f.acceptor, NULL), VIREO_OK);
    CHECK(f.acceptor == NULL);
    check_closed(f.numeric_listener);
    CHECK(connection_info(lookup(&f, f.slots[0].lease)).loop_attached);
    pump_pipeline(&f);
    check_response(peer, 4);
    CHECK(f.seen_ids == 8 && close(peer) == 0);
    fixture_cleanup(&f);
}

static void test_stop_in_callback(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_INET, STOP_IN_CALLBACK, 1, 128, 2);
    int const peer = connect_peer(&f, 5);
    CHECK(run_once(&f).dispatched_count == 1 && f.accepted == 1);
    CHECK(f.slots[0].callbacks == 0);
    vireo_acceptor_info_t state;
    EXPECT(vireo_acceptor_inspect(f.acceptor, &state), VIREO_OK);
    CHECK(!state.loop_attached && !state.callback_active);
    vireo_event_loop_run_info_t const stopped = run_once(&f);
    CHECK(stopped.ready_count == 0 && stopped.dispatched_count == 0 &&
          stopped.stale_count == 0 && stopped.filtered_count == 0);
    CHECK(pool_info(&f).leased_slots == 1);
    vireo_connection_pool_lease_t const lease = f.slots[0].lease;
    EXPECT(vireo_connection_pool_release(f.pool, &f.slots[0].lease, NULL), VIREO_RESULT_BUSY);
    CHECK(lease_equal(lease, f.slots[0].lease));
    EXPECT(vireo_connection_pool_destroy(&f.pool, NULL), VIREO_RESULT_BUSY);
    vireo_connection_t *borrowed = lookup(&f, lease);
    EXPECT(vireo_connection_request_close(borrowed, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
        VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP, NULL), VIREO_OK);
    CHECK(connection_info(borrowed).loop_attached);
    EXPECT(vireo_connection_pool_release(f.pool, &f.slots[0].lease, NULL), VIREO_RESULT_BUSY);
    EXPECT(vireo_connection_detach(borrowed, NULL), VIREO_OK);
    release_slot(&f, &f.slots[0]);
    CHECK(close(peer) == 0);
    fixture_cleanup(&f);
}

static void test_destroy_loop_then_forget(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_UNIX, KEEP, 1, 128, 2);
    int const peer = connect_peer(&f, 6);
    CHECK(run_once(&f).dispatched_count == 1 && f.accepted == 1);
    attach_client(&f, &f.slots[0]);
    EXPECT(vireo_event_loop_destroy(&f.loop, NULL), VIREO_OK);
    CHECK(f.loop == NULL);
    vireo_acceptor_info_t acceptor_state;
    EXPECT(vireo_acceptor_inspect(f.acceptor, &acceptor_state), VIREO_OK);
    CHECK(acceptor_state.loop_attached && !acceptor_state.callback_active);
    EXPECT(vireo_acceptor_destroy(&f.acceptor, NULL), VIREO_RESULT_BUSY);
    vireo_connection_t *borrowed = lookup(&f, f.slots[0].lease);
    CHECK(connection_info(borrowed).loop_attached);
    EXPECT(vireo_connection_pool_release(f.pool, &f.slots[0].lease, NULL), VIREO_RESULT_BUSY);
    /* 正确 loop 已实际消费且没有运行/请求者；不在旧地址上 DEL。 */
    EXPECT(vireo_connection_forget_destroyed_loop(borrowed, NULL), VIREO_OK);
    EXPECT(vireo_acceptor_forget_destroyed_loop(f.acceptor, NULL), VIREO_OK);
    CHECK(!connection_info(borrowed).loop_attached);
    release_slot(&f, &f.slots[0]);
    EXPECT(vireo_acceptor_destroy(&f.acceptor, NULL), VIREO_OK);
    check_closed(f.numeric_listener);
    CHECK(close(peer) == 0);
    fixture_cleanup(&f);
}

static void test_native_reuse(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_INET, PIPELINE, 1, 128, 2);
    f.batch_limit = 1;
    vireo_connection_pool_lease_t previous = {0};
    int previous_fd = -1;
    for (unsigned i = 0; i < 8; ++i) {
        if (i != 0) {
            f.accepted = 0;
            f.completed = 0;
            f.slot_next = 0;
            f.seen_ids = 0;
            EXPECT(vireo_acceptor_set_read_enabled(f.acceptor, true, NULL), VIREO_OK);
        }
        int const peer = connect_peer(&f, (uint8_t)(i + 1));
        CHECK(run_once(&f).dispatched_count == 1 && f.accepted == 1);
        vireo_connection_pool_lease_t const current = f.slots[0].lease;
        if (i != 0) {
            CHECK(current.pool_id == previous.pool_id && current.slot_index == previous.slot_index);
            CHECK(current.generation > previous.generation);
            if (f.slots[0].numeric_fd == previous_fd) ++reused_fds;
            vireo_connection_t *out = NULL;
            EXPECT(vireo_connection_pool_lookup(f.pool, previous, &out), VIREO_RESULT_NOT_FOUND);
            CHECK(out == NULL);
        }
        previous = current;
        previous_fd = f.slots[0].numeric_fd;
        pump_pipeline(&f);
        check_response(peer, (uint8_t)(i + 1));
        CHECK(close(peer) == 0);
    }
    CHECK(f.accept_callbacks == 8);
    fixture_cleanup(&f);
}

int main(void)
{
    unsigned const before = fd_count();
    test_pipeline(AF_INET);
    test_pipeline(AF_UNIX);
    test_rejection(CREATE_RANGE);
    test_rejection(POOL_SLOTS);
    test_rejection(POOL_BUDGET);
    test_rejection(POOL_RANGE);
    test_rejection(LOOP_FULL);
    test_listener_client_independence();
    test_stop_in_callback();
    test_destroy_loop_then_forget();
    test_native_reuse();
    unsigned const after = fd_count();
    CHECK(before == after);
    printf("acceptor integration: %u groups, %u failures, fd %u -> %u; observed TCP fd reuse %u/7\n",
           groups, failures, before, after, reused_fds);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
