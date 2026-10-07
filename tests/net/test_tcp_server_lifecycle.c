/*
- PROJECT : VIREO
- FILE    : test_tcp_server_lifecycle.c
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 空 server 真实依赖装配、预算边界和 fd 恢复
- -- 发布保持、公开快照拒绝、逆序回滚和消费型 IO 的本层验证
 */
#include "net/tcp_server_internal.h"

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
        fprintf(stderr, "fixture %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

static vireo_tcp_server_options_t const options = {3, 2, 1048576, 4096};

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

/* 不比较结构体 padding；独立诊断只承诺语义成员。 */
static bool loop_error_zero(vireo_event_loop_error_t error)
{
    return error.stage == VIREO_EVENT_LOOP_STAGE_NONE && error.system_errno == 0 &&
           error.epoll_error.stage == VIREO_EPOLL_STAGE_NONE && error.epoll_error.system_errno == 0;
}

static bool error_zero(vireo_tcp_server_error_t error)
{
    return error.stage == VIREO_TCP_SERVER_STAGE_NONE && loop_error_zero(error.loop_error) &&
           error.pool_error.stage == VIREO_CONNECTION_POOL_STAGE_NONE &&
           error.acceptor_error.stage == VIREO_ACCEPTOR_STAGE_NONE && error.acceptor_error.system_errno == 0 &&
           error.cleanup_result == VIREO_OK && error.cleanup_stage == VIREO_TCP_SERVER_STAGE_NONE &&
           loop_error_zero(error.cleanup_loop_error) &&
           error.cleanup_pool_error.stage == VIREO_CONNECTION_POOL_STAGE_NONE &&
           error.cleanup_acceptor_error.stage == VIREO_ACCEPTOR_STAGE_NONE &&
           error.cleanup_acceptor_error.system_errno == 0;
}

typedef struct fixture {
    vireo_tcp_server_t *owner;
    bool constructing;
    bool fail_allocate;
    bool cleanup_io;
    bool pool_busy;
    vireo_result_t loop_create_result;
    vireo_result_t pool_create_result;
    vireo_result_t loop_inspect_result;
    vireo_result_t pool_inspect_result;
    unsigned corrupt_loop;
    unsigned corrupt_pool;
    unsigned allocations;
    unsigned frees;
    unsigned live;
    unsigned loop_creates;
    unsigned loop_destroys;
    unsigned pool_creates;
    unsigned pool_destroys;
    size_t control_bytes;
    vireo_event_loop_options_t loop_options;
    vireo_connection_pool_options_t pool_options;
    char order[128];
    size_t order_size;
} fixture_t;

static void record(fixture_t *f, char step)
{
    REQUIRE(f->order_size + 1 < sizeof(f->order));
    f->order[f->order_size++] = step;
    f->order[f->order_size] = '\0';
    if (f->constructing) CHECK(f->owner == NULL);
    errno = E2BIG;
}

static void *allocate_control(void *context, size_t bytes)
{
    fixture_t *f = context;
    record(f, 'A');
    ++f->allocations;
    f->control_bytes = bytes;
    if (f->fail_allocate) return NULL;
    void *memory = malloc(bytes);
    REQUIRE(memory != NULL);
    ++f->live;
    return memory;
}

static void free_control(void *context, void *memory)
{
    fixture_t *f = context;
    record(f, 'F');
    CHECK(f->live == 1 && memory != NULL);
    --f->live;
    ++f->frees;
    free(memory);
}

static vireo_result_t create_loop(void *context, vireo_event_loop_options_t const *input,
                                  vireo_event_loop_t **owner, vireo_event_loop_error_t *error)
{
    fixture_t *f = context;
    record(f, 'L');
    ++f->loop_creates;
    f->loop_options = *input;
    CHECK(*owner == NULL && f->live == 1);
    if (f->loop_create_result != VIREO_OK) {
        *error = (vireo_event_loop_error_t){
            VIREO_EVENT_LOOP_STAGE_WAKE_CREATE,
            {VIREO_EPOLL_STAGE_CREATE, ENFILE}, EMFILE
        };
        return f->loop_create_result;
    }
    return vireo_event_loop_create(input, owner, error);
}

/* 仅污染公开数值副本；真实 opaque loop 仍保持有效空态。 */
static vireo_result_t inspect_loop(void *context, vireo_event_loop_t const *loop,
                                   vireo_event_loop_info_t *info)
{
    fixture_t *f = context;
    record(f, 'I');
    if (f->loop_inspect_result != VIREO_OK) return f->loop_inspect_result;
    vireo_result_t const result = vireo_event_loop_inspect(loop, info);
    REQUIRE(result == VIREO_OK);
    switch (f->corrupt_loop) {
    case 1: ++info->event_capacity; break;
    case 2: ++info->registration_capacity; break;
    case 3: info->registered_count = 1; break;
    case 4: info->stop_requested = true; break;
    case 5: info->loop_id = 0; break;
    case 6: ++info->max_memory_bytes; break;
    case 7: ++info->allocation_bytes; break;
    case 8: info->loop_allocation_bytes = SIZE_MAX; break;
    case 9: info->events_bytes = SIZE_MAX; break;
    case 10: info->available_count = 0; break;
    case 11: info->registrations_bytes = 0; break;
    default: break;
    }
    return result;
}

/* 先调用 public destroy 消费真实资源，再模拟 IO；不是内核 close 故障。 */
static vireo_result_t destroy_loop(void *context, vireo_event_loop_t **owner,
                                   vireo_event_loop_error_t *error)
{
    fixture_t *f = context;
    record(f, 'l');
    ++f->loop_destroys;
    REQUIRE(vireo_event_loop_destroy(owner, error) == VIREO_OK);
    CHECK(*owner == NULL);
    if (f->cleanup_io) {
        *error = (vireo_event_loop_error_t){
            VIREO_EVENT_LOOP_STAGE_DESTROY_EPOLL,
            {VIREO_EPOLL_STAGE_CLOSE, EINTR}, EIO
        };
        return VIREO_RESULT_IO;
    }
    return VIREO_OK;
}

static vireo_result_t create_pool(void *context, vireo_connection_pool_options_t const *input,
                                  vireo_connection_pool_t **owner,
                                  vireo_connection_pool_error_t *error)
{
    fixture_t *f = context;
    record(f, 'P');
    ++f->pool_creates;
    f->pool_options = *input;
    CHECK(*owner == NULL);
    if (f->pool_create_result != VIREO_OK) {
        error->stage = VIREO_CONNECTION_POOL_STAGE_CREATE_STORAGE;
        return f->pool_create_result;
    }
    return vireo_connection_pool_create(input, owner, error);
}

static vireo_result_t inspect_pool(void *context, vireo_connection_pool_t const *pool,
                                   vireo_connection_pool_info_t *info)
{
    fixture_t *f = context;
    record(f, 'J');
    if (f->pool_inspect_result != VIREO_OK) return f->pool_inspect_result;
    vireo_result_t const result = vireo_connection_pool_inspect(pool, info);
    REQUIRE(result == VIREO_OK);
    switch (f->corrupt_pool) {
    case 1: ++info->capacity; break;
    case 2: info->leased_slots = 1; break;
    case 3: info->available_slots = 0; break;
    case 4: info->buffer_capacity_bytes = 1; break;
    case 5: ++info->max_buffer_bytes; break;
    case 6: ++info->max_memory_bytes; break;
    case 7: ++info->allocation_bytes; break;
    case 8: info->container_allocation_bytes = SIZE_MAX; break;
    case 9: info->storage_allocation_bytes = 0; break;
    case 10: info->index_bytes = 0; break;
    default: break;
    }
    return result;
}

static vireo_result_t destroy_pool(void *context, vireo_connection_pool_t **owner,
                                   vireo_connection_pool_error_t *error)
{
    fixture_t *f = context;
    record(f, 'p');
    ++f->pool_destroys;
    if (f->pool_busy) {
        error->stage = VIREO_CONNECTION_POOL_STAGE_DESTROY_STORAGE;
        return VIREO_RESULT_BUSY;
    }
    return vireo_connection_pool_destroy(owner, error);
}

static vireo_tcp_server_ops_t make_ops(fixture_t *f)
{
    return (vireo_tcp_server_ops_t){
        f, allocate_control, free_control, create_loop, inspect_loop, destroy_loop,
        create_pool, inspect_pool, destroy_pool
    };
}

static vireo_result_t construct(fixture_t *f, vireo_tcp_server_options_t const *input,
                                 vireo_tcp_server_error_t *error)
{
    vireo_tcp_server_ops_t ops = make_ops(f);
    f->constructing = true;
    errno = EDOM;
    vireo_result_t const result = vireo_tcp_server_create_with_ops(input, &ops, &f->owner, error);
    CHECK(errno == EDOM);
    f->constructing = false;
    /* 销毁仍须使用对象内副本，不依赖已结束的局部 ops 地址。 */
    ops.allocate = NULL;
    return result;
}

static void destroy_fixture(fixture_t *f)
{
    errno = EDOM;
    CHECK(vireo_tcp_server_destroy(&f->owner, NULL) == VIREO_OK);
    CHECK(errno == EDOM && f->owner == NULL && f->live == 0);
}

static void test_normal(void)
{
    ++groups;
    unsigned const before = fd_count();
    vireo_tcp_server_t *owner = NULL;
    vireo_tcp_server_error_t error;
    memset(&error, 0xa5, sizeof(error));
    errno = EDOM;
    REQUIRE(vireo_tcp_server_create(&options, &owner, &error) == VIREO_OK);
    CHECK(errno == EDOM && error_zero(error));
    CHECK(fd_count() == before + 3); /* loop 的 epoll 和 pipe 两端，不是监听 fd。 */
    vireo_tcp_server_info_t info = {0};
    errno = EDOM;
    CHECK(vireo_tcp_server_inspect(owner, &info) == VIREO_OK && errno == EDOM);
    CHECK(info.connection_capacity == 3 && info.registration_capacity == 4 && info.event_capacity == 2);
    CHECK(info.allocation_bytes == info.server_allocation_bytes + info.loop_allocation_bytes +
                                  info.pool_allocation_bytes);
    CHECK(info.allocation_bytes <= options.max_memory_bytes && info.connection_count == 0 &&
          info.available_connections == 3 && info.buffer_capacity_bytes == 0 &&
          info.max_buffer_bytes == 4096);
    CHECK(vireo_tcp_server_destroy(&owner, &error) == VIREO_OK && errno == EDOM && owner == NULL);
    CHECK(error_zero(error));
    CHECK(vireo_tcp_server_destroy(&owner, &error) == VIREO_OK && errno == EDOM && error_zero(error));
    CHECK(fd_count() == before);
}

static void test_parameters(void)
{
    ++groups;
    fixture_t f = {0};
    vireo_tcp_server_ops_t const ops = make_ops(&f);
    vireo_tcp_server_error_t error;
    errno = EDOM;
    CHECK(vireo_tcp_server_create(NULL, &f.owner, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM && error_zero(error));
    CHECK(vireo_tcp_server_create(&options, NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT && errno == EDOM);
    for (unsigned i = 0; i < 4; ++i) {
        vireo_tcp_server_options_t input = options;
        if (i == 0) input.connection_capacity = 0;
        if (i == 1) input.event_capacity = 0;
        if (i == 2) input.max_memory_bytes = 0;
        if (i == 3) input.max_buffer_bytes = 0;
        CHECK(construct(&f, &input, &error) == VIREO_RESULT_INVALID_ARGUMENT && error_zero(error));
    }
    for (unsigned i = 0; i < 4; ++i) {
        vireo_tcp_server_options_t input = options;
        if (i == 0) input.connection_capacity = 65536;
        if (i == 1) input.event_capacity = VIREO_EVENT_LOOP_MAX_EVENTS + 1;
        if (i == 2) input.max_memory_bytes = VIREO_TCP_SERVER_MAX_MEMORY + 1;
        if (i == 3) input.max_buffer_bytes = VIREO_CONNECTION_POOL_MAX_BUFFER_MEMORY + 1;
        CHECK(construct(&f, &input, &error) == VIREO_RESULT_RANGE && error_zero(error));
    }
    vireo_tcp_server_options_t input = options;
    input.connection_capacity = SIZE_MAX;
    CHECK(construct(&f, &input, NULL) == VIREO_RESULT_RANGE);
    CHECK(f.owner == NULL && f.allocations == 0 && f.loop_creates == 0);
    CHECK(vireo_tcp_server_create_with_ops(&options, NULL, &f.owner, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    for (unsigned i = 0; i < 8; ++i) {
        vireo_tcp_server_ops_t missing = ops;
        if (i == 0) missing.allocate = NULL;
        if (i == 1) missing.deallocate = NULL;
        if (i == 2) missing.create_loop = NULL;
        if (i == 3) missing.inspect_loop = NULL;
        if (i == 4) missing.destroy_loop = NULL;
        if (i == 5) missing.create_pool = NULL;
        if (i == 6) missing.inspect_pool = NULL;
        if (i == 7) missing.destroy_pool = NULL;
        CHECK(vireo_tcp_server_create_with_ops(&options, &missing, &f.owner, &error) ==
              VIREO_RESULT_INVALID_ARGUMENT && error_zero(error));
    }
    REQUIRE(construct(&f, &options, NULL) == VIREO_OK);
    vireo_tcp_server_t *original = f.owner;
    CHECK(vireo_tcp_server_create(&options, &f.owner, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(f.owner == original && errno == EDOM && error_zero(error));
    vireo_tcp_server_info_t info;
    unsigned char saved[sizeof(info)];
    memset(&info, 0xa5, sizeof(info));
    memcpy(saved, &info, sizeof(info));
    CHECK(vireo_tcp_server_inspect(NULL, &info) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(saved, &info, sizeof(info)) == 0 && errno == EDOM);
    CHECK(vireo_tcp_server_inspect(f.owner, NULL) == VIREO_RESULT_INVALID_ARGUMENT && errno == EDOM);
    CHECK(vireo_tcp_server_destroy(NULL, &error) == VIREO_RESULT_INVALID_ARGUMENT && error_zero(error));
    destroy_fixture(&f);
}

static void test_budget(void)
{
    ++groups;
    fixture_t f = {0};
    REQUIRE(construct(&f, &options, NULL) == VIREO_OK);
    vireo_tcp_server_info_t info;
    REQUIRE(vireo_tcp_server_inspect(f.owner, &info) == VIREO_OK);
    CHECK(f.loop_options.max_memory_bytes == options.max_memory_bytes - info.server_allocation_bytes);
    CHECK(f.pool_options.max_memory_bytes == options.max_memory_bytes - info.server_allocation_bytes -
                                                 info.loop_allocation_bytes);
    destroy_fixture(&f);
    vireo_tcp_server_options_t input = options;
    input.max_memory_bytes = info.allocation_bytes;
    REQUIRE(vireo_tcp_server_create(&input, &f.owner, NULL) == VIREO_OK);
    vireo_tcp_server_info_t exact;
    CHECK(vireo_tcp_server_inspect(f.owner, &exact) == VIREO_OK && exact.allocation_bytes == input.max_memory_bytes);
    CHECK(vireo_tcp_server_destroy(&f.owner, NULL) == VIREO_OK);
    input.max_memory_bytes = info.allocation_bytes - 1;
    CHECK(vireo_tcp_server_create(&input, &f.owner, NULL) == VIREO_RESULT_RANGE && f.owner == NULL);
    input.max_memory_bytes = info.server_allocation_bytes;
    CHECK(vireo_tcp_server_create(&input, &f.owner, NULL) == VIREO_RESULT_RANGE);
    input.max_memory_bytes = info.server_allocation_bytes + 1;
    CHECK(vireo_tcp_server_create(&input, &f.owner, NULL) == VIREO_RESULT_RANGE);
    input.max_memory_bytes = info.server_allocation_bytes + info.loop_allocation_bytes;
    CHECK(vireo_tcp_server_create(&input, &f.owner, NULL) == VIREO_RESULT_RANGE && f.owner == NULL);
    input.max_memory_bytes = 1;
    CHECK(vireo_tcp_server_create(&input, &f.owner, NULL) == VIREO_RESULT_RANGE && errno == EDOM);
}

static void test_capacities(void)
{
    ++groups;
    vireo_tcp_server_options_t input = {
        VIREO_TCP_SERVER_MAX_CONNECTIONS, VIREO_EVENT_LOOP_MAX_EVENTS,
        VIREO_TCP_SERVER_MAX_MEMORY, VIREO_CONNECTION_POOL_MAX_BUFFER_MEMORY
    };
    vireo_tcp_server_t *owner = NULL;
    REQUIRE(vireo_tcp_server_create(&input, &owner, NULL) == VIREO_OK);
    vireo_tcp_server_info_t info;
    CHECK(vireo_tcp_server_inspect(owner, &info) == VIREO_OK && info.registration_capacity == 65536 &&
          info.connection_count == 0 && info.buffer_capacity_bytes == 0);
    CHECK(vireo_tcp_server_destroy(&owner, NULL) == VIREO_OK);
    input.connection_capacity = 10;
    input.event_capacity = 1;
    input.max_buffer_bytes = 1;
    REQUIRE(vireo_tcp_server_create(&input, &owner, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_inspect(owner, &info) == VIREO_OK && info.event_capacity == 1 &&
          info.registration_capacity == 11 && info.available_connections == 10 && info.max_buffer_bytes == 1);
    CHECK(vireo_tcp_server_destroy(&owner, NULL) == VIREO_OK);
}

static void test_creation_failures(void)
{
    ++groups;
    unsigned const before = fd_count();
    for (unsigned i = 0; i < 5; ++i) {
        fixture_t f = {0};
        vireo_tcp_server_error_t error;
        if (i == 0) f.fail_allocate = true;
        if (i == 1) f.loop_create_result = VIREO_RESULT_IO;
        if (i == 2) f.loop_inspect_result = VIREO_RESULT_INTERNAL;
        if (i == 3) f.pool_create_result = VIREO_RESULT_NO_MEMORY;
        if (i == 4) f.pool_inspect_result = VIREO_RESULT_INTERNAL;
        vireo_result_t const expected[5] = {VIREO_RESULT_NO_MEMORY, VIREO_RESULT_IO,
            VIREO_RESULT_INTERNAL, VIREO_RESULT_NO_MEMORY, VIREO_RESULT_INTERNAL};
        vireo_tcp_server_stage_t const stage[5] = {VIREO_TCP_SERVER_STAGE_ALLOCATE_CONTROL,
            VIREO_TCP_SERVER_STAGE_CREATE_LOOP, VIREO_TCP_SERVER_STAGE_INSPECT_LOOP,
            VIREO_TCP_SERVER_STAGE_CREATE_POOL, VIREO_TCP_SERVER_STAGE_INSPECT_POOL};
        char const *const order[5] = {"A", "ALF", "ALIlF", "ALIPlF", "ALIPJplF"};
        CHECK(construct(&f, &options, &error) == expected[i] && error.stage == stage[i]);
        CHECK(f.owner == NULL && f.live == 0 && error.cleanup_result == VIREO_OK);
        CHECK(strcmp(f.order, order[i]) == 0);
        if (i == 1) CHECK(error.loop_error.stage == VIREO_EVENT_LOOP_STAGE_WAKE_CREATE &&
                          error.loop_error.system_errno == EMFILE &&
                          error.loop_error.epoll_error.system_errno == ENFILE);
        if (i == 3) CHECK(error.pool_error.stage == VIREO_CONNECTION_POOL_STAGE_CREATE_STORAGE);
        CHECK(fd_count() == before);
    }
}

static void test_bad_creation_snapshots(void)
{
    ++groups;
    unsigned const before = fd_count();
    for (unsigned layer = 0; layer < 2; ++layer) {
        unsigned const count = layer == 0 ? 11 : 10;
        for (unsigned i = 1; i <= count; ++i) {
            fixture_t f = {0};
            if (layer == 0) f.corrupt_loop = i;
            else f.corrupt_pool = i;
            vireo_tcp_server_error_t error;
            CHECK(construct(&f, &options, &error) == VIREO_RESULT_INTERNAL);
            CHECK(error.stage == (layer == 0 ? VIREO_TCP_SERVER_STAGE_INSPECT_LOOP :
                                              VIREO_TCP_SERVER_STAGE_INSPECT_POOL));
            CHECK(f.owner == NULL && f.live == 0 && f.frees == 1 && f.loop_destroys == 1);
            CHECK(f.pool_destroys == (layer == 0 ? 0U : 1U));
            CHECK(strcmp(f.order, layer == 0 ? "ALIlF" : "ALIPJplF") == 0);
            CHECK(fd_count() == before);
        }
    }
}

static void test_main_and_cleanup_errors(void)
{
    ++groups;
    unsigned const before = fd_count();
    for (unsigned i = 0; i < 2; ++i) {
        fixture_t f = {0};
        f.cleanup_io = true;
        if (i == 0) f.pool_create_result = VIREO_RESULT_NO_MEMORY;
        else f.pool_inspect_result = VIREO_RESULT_INTERNAL;
        vireo_tcp_server_error_t error;
        CHECK(construct(&f, &options, &error) == (i == 0 ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_INTERNAL));
        CHECK(error.stage == (i == 0 ? VIREO_TCP_SERVER_STAGE_CREATE_POOL : VIREO_TCP_SERVER_STAGE_INSPECT_POOL));
        CHECK(error.cleanup_result == VIREO_RESULT_IO &&
              error.cleanup_stage == VIREO_TCP_SERVER_STAGE_DESTROY_LOOP &&
              error.cleanup_loop_error.stage == VIREO_EVENT_LOOP_STAGE_DESTROY_EPOLL &&
              error.cleanup_loop_error.epoll_error.stage == VIREO_EPOLL_STAGE_CLOSE &&
              error.cleanup_loop_error.epoll_error.system_errno == EINTR &&
              error.cleanup_loop_error.system_errno == EIO);
        CHECK(f.owner == NULL && f.live == 0 && f.loop_destroys == 1 && f.frees == 1);
        CHECK(fd_count() == before);
    }
    fixture_t f = {0};
    f.cleanup_io = true;
    f.pool_create_result = VIREO_RESULT_NO_MEMORY;
    CHECK(construct(&f, &options, NULL) == VIREO_RESULT_NO_MEMORY && f.owner == NULL && f.live == 0);
    CHECK(fd_count() == before);
}

static void test_inspect_preservation(void)
{
    ++groups;
    fixture_t f = {0};
    REQUIRE(construct(&f, &options, NULL) == VIREO_OK);
    for (unsigned i = 0; i < 23; ++i) {
        vireo_tcp_server_info_t info;
        unsigned char saved[sizeof(info)];
        memset(&info, 0xa5, sizeof(info));
        memcpy(saved, &info, sizeof(info));
        if (i == 0) f.loop_inspect_result = VIREO_RESULT_INTERNAL;
        else if (i == 1) f.pool_inspect_result = VIREO_RESULT_INTERNAL;
        else if (i <= 12) f.corrupt_loop = i - 1;
        else f.corrupt_pool = i - 12;
        errno = EDOM;
        if (i == 5) { /* M11：运行态永久停止合法；构造态case4拒绝仍单独保留。 */
            CHECK(vireo_tcp_server_inspect(f.owner, &info) == VIREO_OK && errno == EDOM);
            CHECK(info.stop_requested && !info.running_active && info.connection_count == 0);
        } else {
            CHECK(vireo_tcp_server_inspect(f.owner, &info) == VIREO_RESULT_INTERNAL && errno == EDOM);
            CHECK(memcmp(saved, &info, sizeof(info)) == 0);
        }
        f.loop_inspect_result = f.pool_inspect_result = VIREO_OK;
        f.corrupt_loop = f.corrupt_pool = 0;
    }
    vireo_tcp_server_info_t info;
    CHECK(vireo_tcp_server_inspect(f.owner, &info) == VIREO_OK && info.connection_count == 0);
    destroy_fixture(&f);
}

static void test_destroy_refusal(void)
{
    ++groups;
    unsigned const before = fd_count();
    fixture_t f = {0};
    REQUIRE(construct(&f, &options, NULL) == VIREO_OK);
    vireo_tcp_server_t *original = f.owner;
    f.pool_busy = true;
    vireo_tcp_server_error_t error;
    errno = EDOM;
    CHECK(vireo_tcp_server_destroy(&f.owner, &error) == VIREO_RESULT_BUSY && errno == EDOM);
    CHECK(f.owner == original && f.live == 1 && f.loop_destroys == 0 && f.frees == 0);
    CHECK(error.stage == VIREO_TCP_SERVER_STAGE_DESTROY_POOL &&
          error.pool_error.stage == VIREO_CONNECTION_POOL_STAGE_DESTROY_STORAGE &&
          loop_error_zero(error.loop_error) && error.cleanup_result == VIREO_OK);
    CHECK(fd_count() == before + 3);
    vireo_tcp_server_info_t info;
    CHECK(vireo_tcp_server_inspect(f.owner, &info) == VIREO_OK);
    f.pool_busy = false;
    destroy_fixture(&f);
    CHECK(fd_count() == before);
}

static void test_destroy_consuming_io(void)
{
    ++groups;
    unsigned const before = fd_count();
    for (unsigned i = 0; i < 2; ++i) {
        fixture_t f = {0};
        REQUIRE(construct(&f, &options, NULL) == VIREO_OK);
        f.cleanup_io = true;
        vireo_tcp_server_error_t error;
        errno = EDOM;
        CHECK(vireo_tcp_server_destroy(&f.owner, i == 0 ? &error : NULL) == VIREO_RESULT_IO && errno == EDOM);
        CHECK(f.owner == NULL && f.live == 0 && f.pool_destroys == 1 && f.loop_destroys == 1 && f.frees == 1);
        CHECK(strcmp(f.order, "ALIPJplF") == 0);
        if (i == 0) CHECK(error.stage == VIREO_TCP_SERVER_STAGE_DESTROY_LOOP &&
                          error.loop_error.epoll_error.system_errno == EINTR &&
                          error.loop_error.system_errno == EIO && error.cleanup_result == VIREO_OK);
        CHECK(vireo_tcp_server_destroy(&f.owner, NULL) == VIREO_OK && f.loop_destroys == 1);
        CHECK(fd_count() == before);
    }
}

int main(void)
{
    unsigned const before = fd_count();
    test_normal();
    test_parameters();
    test_budget();
    test_capacities();
    test_creation_failures();
    test_bad_creation_snapshots();
    test_main_and_cleanup_errors();
    test_inspect_preservation();
    test_destroy_refusal();
    test_destroy_consuming_io();
    unsigned const after = fd_count();
    CHECK(after == before);
    printf("tcp_server lifecycle: %u groups, %u failures; fd %u -> %u\n",
           groups, failures, before, after);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
