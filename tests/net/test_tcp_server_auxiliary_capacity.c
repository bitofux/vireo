/*
- PROJECT : VIREO
- FILE    : test_tcp_server_auxiliary_capacity.c
- AUTHOR  : bitofux
- DATE    : 2026-10-13
- BRIEF   : 此模块负责：
- -- 显式辅助容量、旧入口兼容、真实总预算与 fd 恢复
- -- 仅本 server 的公开依赖 seam 验证失败保持及逆序回滚
 */
#include "net/tcp_server_internal.h"

#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned failures;
#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); ++failures; \
} } while (0)
#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "fixture %s:%d: %s\n", __FILE__, __LINE__, #x); exit(EXIT_FAILURE); \
} } while (0)

static vireo_tcp_server_options_t const options = {3, 2, 1048576, 4096};

static unsigned fd_count(void)
{
    DIR *d = opendir("/proc/self/fd");
    REQUIRE(d != NULL);
    unsigned n = 0;
    struct dirent *item;
    while ((item = readdir(d)) != NULL) if (item->d_name[0] != '.') ++n;
    REQUIRE(closedir(d) == 0);
    return n;
}

static bool error_zero(vireo_tcp_server_error_t e)
{
    return e.stage == VIREO_TCP_SERVER_STAGE_NONE &&
        e.loop_error.stage == VIREO_EVENT_LOOP_STAGE_NONE && e.loop_error.system_errno == 0 &&
        e.loop_error.epoll_error.stage == VIREO_EPOLL_STAGE_NONE && e.loop_error.epoll_error.system_errno == 0 &&
        e.pool_error.stage == VIREO_CONNECTION_POOL_STAGE_NONE &&
        e.acceptor_error.stage == VIREO_ACCEPTOR_STAGE_NONE && e.acceptor_error.system_errno == 0 &&
        e.cleanup_result == VIREO_OK && e.cleanup_stage == VIREO_TCP_SERVER_STAGE_NONE &&
        e.cleanup_loop_error.stage == VIREO_EVENT_LOOP_STAGE_NONE && e.cleanup_loop_error.system_errno == 0 &&
        e.cleanup_loop_error.epoll_error.stage == VIREO_EPOLL_STAGE_NONE && e.cleanup_loop_error.epoll_error.system_errno == 0 &&
        e.cleanup_pool_error.stage == VIREO_CONNECTION_POOL_STAGE_NONE &&
        e.cleanup_acceptor_error.stage == VIREO_ACCEPTOR_STAGE_NONE && e.cleanup_acceptor_error.system_errno == 0;
}

static void destroy(vireo_tcp_server_t **owner)
{
    errno = EDOM;
    CHECK(vireo_tcp_server_destroy(owner, NULL) == VIREO_OK);
    CHECK(errno == EDOM && *owner == NULL);
}

static void test_old_and_auxiliary(void)
{
    vireo_tcp_server_t *old = NULL, *extra = NULL;
    vireo_tcp_server_info_t a = {0}, b = {0};
    errno = EDOM;
    REQUIRE(vireo_tcp_server_create(&options, &old, NULL) == VIREO_OK);
    CHECK(errno == EDOM);
    REQUIRE(vireo_tcp_server_create_with_auxiliary_capacity(&options, 7, &extra, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_inspect(old, &a) == VIREO_OK);
    REQUIRE(vireo_tcp_server_inspect(extra, &b) == VIREO_OK);
    CHECK(a.registration_capacity == 4 && a.auxiliary_registration_capacity == 0);
    CHECK(b.registration_capacity == 11 && b.auxiliary_registration_capacity == 7);
    CHECK(b.connection_capacity == 3 && b.available_connections == 3 && b.connection_count == 0);
    CHECK(b.event_capacity == 2 && b.registered_connections == 0 && !b.listener_owned);
    CHECK(b.server_allocation_bytes == a.server_allocation_bytes && b.pool_allocation_bytes == a.pool_allocation_bytes);
    CHECK(b.client_slots_bytes == a.client_slots_bytes && b.loop_allocation_bytes > a.loop_allocation_bytes);
    CHECK(b.allocation_bytes - a.allocation_bytes == b.loop_allocation_bytes - a.loop_allocation_bytes);
    CHECK(b.allocation_bytes == b.server_allocation_bytes + b.loop_allocation_bytes + b.pool_allocation_bytes);
    destroy(&extra); destroy(&old);
}

static void test_total_maximum(void)
{
    vireo_tcp_server_options_t o = options;
    o.connection_capacity = 1; o.max_memory_bytes = VIREO_TCP_SERVER_MAX_MEMORY;
    vireo_tcp_server_t *owner = NULL;
    unsigned const before = fd_count();
    REQUIRE(vireo_tcp_server_create_with_auxiliary_capacity(&o, 65534, &owner, NULL) == VIREO_OK);
    CHECK(fd_count() == before + 3);
    vireo_tcp_server_info_t i = {0};
    REQUIRE(vireo_tcp_server_inspect(owner, &i) == VIREO_OK);
    CHECK(i.registration_capacity == 65536 && i.auxiliary_registration_capacity == 65534);
    CHECK(i.connection_capacity == 1 && i.available_connections == 1 && i.event_capacity == 2);
    destroy(&owner);
}

static void expect_reject(vireo_tcp_server_options_t const *o, size_t extra, vireo_result_t want)
{
    vireo_tcp_server_t *owner = NULL;
    vireo_tcp_server_error_t e;
    memset(&e, 0x5a, sizeof(e)); errno = EDOM;
    CHECK(vireo_tcp_server_create_with_auxiliary_capacity(o, extra, &owner, &e) == want);
    CHECK(owner == NULL && errno == EDOM && error_zero(e));
}

static void test_basic_priority(void)
{
    expect_reject(NULL, SIZE_MAX, VIREO_RESULT_INVALID_ARGUMENT);
    expect_reject(&options, 0, VIREO_RESULT_INVALID_ARGUMENT);
    vireo_tcp_server_error_t e;
    memset(&e, 0x5a, sizeof(e)); errno = EDOM;
    CHECK(vireo_tcp_server_create_with_auxiliary_capacity(&options, 1, NULL, &e) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM && error_zero(e));
    vireo_tcp_server_t *owner = NULL;
    REQUIRE(vireo_tcp_server_create(&options, &owner, NULL) == VIREO_OK);
    vireo_tcp_server_t *const saved = owner;
    CHECK(vireo_tcp_server_create_with_auxiliary_capacity(&options, SIZE_MAX, &owner, &e) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == saved && error_zero(e)); destroy(&owner);
}

static void test_original_zero_options(void)
{
    vireo_tcp_server_options_t o = options;
    o.connection_capacity = 0; expect_reject(&o, SIZE_MAX, VIREO_RESULT_INVALID_ARGUMENT);
    o = options; o.event_capacity = 0; expect_reject(&o, 1, VIREO_RESULT_INVALID_ARGUMENT);
    o = options; o.max_memory_bytes = 0; expect_reject(&o, 1, VIREO_RESULT_INVALID_ARGUMENT);
    o = options; o.max_buffer_bytes = 0; expect_reject(&o, 1, VIREO_RESULT_INVALID_ARGUMENT);
}

static void test_checked_sum(void)
{
    expect_reject(&options, SIZE_MAX, VIREO_RESULT_OVERFLOW);
    expect_reject(&options, SIZE_MAX - 3, VIREO_RESULT_OVERFLOW);
    expect_reject(&options, SIZE_MAX - 4, VIREO_RESULT_RANGE);
    expect_reject(&options, 65533, VIREO_RESULT_RANGE);
}

static void test_original_hard_limits_first(void)
{
    vireo_tcp_server_options_t o = options;
    o.connection_capacity = VIREO_TCP_SERVER_MAX_CONNECTIONS + 1;
    expect_reject(&o, SIZE_MAX, VIREO_RESULT_RANGE);
    o = options; o.event_capacity = VIREO_EVENT_LOOP_MAX_EVENTS + 1;
    expect_reject(&o, SIZE_MAX, VIREO_RESULT_RANGE);
    o = options; o.max_memory_bytes = VIREO_TCP_SERVER_MAX_MEMORY + 1;
    expect_reject(&o, SIZE_MAX, VIREO_RESULT_RANGE);
    o = options; o.max_buffer_bytes = VIREO_CONNECTION_POOL_MAX_BUFFER_MEMORY + 1;
    expect_reject(&o, SIZE_MAX, VIREO_RESULT_RANGE);
}

static void test_old_maximum_and_extra_range(void)
{
    vireo_tcp_server_options_t o = options;
    o.connection_capacity = VIREO_TCP_SERVER_MAX_CONNECTIONS;
    o.max_memory_bytes = VIREO_TCP_SERVER_MAX_MEMORY;
    expect_reject(&o, 1, VIREO_RESULT_RANGE);
    vireo_tcp_server_t *owner = NULL;
    REQUIRE(vireo_tcp_server_create(&o, &owner, NULL) == VIREO_OK);
    vireo_tcp_server_info_t i = {0};
    REQUIRE(vireo_tcp_server_inspect(owner, &i) == VIREO_OK);
    CHECK(i.registration_capacity == 65536 && i.auxiliary_registration_capacity == 0);
    CHECK(i.available_connections == VIREO_TCP_SERVER_MAX_CONNECTIONS);
    destroy(&owner);
}

static void test_exact_budget_and_short(void)
{
    vireo_tcp_server_t *owner = NULL;
    vireo_tcp_server_info_t old_info = {0}, i = {0};
    REQUIRE(vireo_tcp_server_create(&options, &owner, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_inspect(owner, &old_info) == VIREO_OK); destroy(&owner);
    REQUIRE(vireo_tcp_server_create_with_auxiliary_capacity(&options, 1024, &owner, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_inspect(owner, &i) == VIREO_OK); destroy(&owner);
    CHECK(i.allocation_bytes > old_info.allocation_bytes);
    vireo_tcp_server_options_t o = options; o.max_memory_bytes = i.allocation_bytes;
    REQUIRE(vireo_tcp_server_create_with_auxiliary_capacity(&o, 1024, &owner, NULL) == VIREO_OK);
    vireo_tcp_server_info_t exact = {0};
    REQUIRE(vireo_tcp_server_inspect(owner, &exact) == VIREO_OK);
    CHECK(exact.allocation_bytes == o.max_memory_bytes && exact.auxiliary_registration_capacity == 1024);
    destroy(&owner);
    --o.max_memory_bytes;
    errno = EDOM;
    CHECK(vireo_tcp_server_create_with_auxiliary_capacity(&o, 1024, &owner, NULL) == VIREO_RESULT_RANGE);
    CHECK(owner == NULL && errno == EDOM);
    o.max_memory_bytes = old_info.allocation_bytes;
    REQUIRE(vireo_tcp_server_create(&o, &owner, NULL) == VIREO_OK); destroy(&owner);
    CHECK(vireo_tcp_server_create_with_auxiliary_capacity(&o, 1024, &owner, NULL) == VIREO_RESULT_RANGE);
    CHECK(owner == NULL);
}

static void test_stop_and_inspect_holding(void)
{
    vireo_tcp_server_t *owner = NULL;
    REQUIRE(vireo_tcp_server_create_with_auxiliary_capacity(&options, 1, &owner, NULL) == VIREO_OK);
    vireo_tcp_server_info_t i;
    memset(&i, 0x5a, sizeof(i)); unsigned char saved[sizeof(i)]; memcpy(saved, &i, sizeof(i));
    errno = EDOM;
    CHECK(vireo_tcp_server_inspect(NULL, &i) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(saved, &i, sizeof(i)) == 0 && errno == EDOM);
    CHECK(vireo_tcp_server_inspect(owner, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    REQUIRE(vireo_tcp_server_request_stop(owner, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_inspect(owner, &i) == VIREO_OK);
    CHECK(i.stop_requested && i.auxiliary_registration_capacity == 1 && i.registration_capacity == 5);
    destroy(&owner);
}

/** 模拟只在本层边界；资源创建/释放仍调用依赖的 public API。 */
typedef struct model {
    unsigned fault; /**< 1申请，2loop创建，3loop观测，4loop形态，5pool创建，6pool观测，7pool形态。 */
    vireo_result_t failure_result;
    bool cleanup_io;
    unsigned allocations;
    unsigned frees;
    unsigned loop_destroys;
    unsigned pool_destroys;
    size_t registrations;
    size_t pool_capacity;
    char order[32];
    size_t steps;
} model_t;

static void mark(model_t *m, char step)
{
    REQUIRE(m->steps + 1 < sizeof(m->order));
    m->order[m->steps++] = step; m->order[m->steps] = '\0'; errno = E2BIG;
}
static void *model_allocate(void *ctx, size_t bytes)
{
    model_t *m = ctx; mark(m, 'A'); ++m->allocations;
    return m->fault == 1 ? NULL : malloc(bytes);
}
static void model_free(void *ctx, void *memory)
{
    model_t *m = ctx; mark(m, 'F'); ++m->frees; free(memory);
}
static vireo_result_t model_loop_create(void *ctx, vireo_event_loop_options_t const *o,
    vireo_event_loop_t **owner, vireo_event_loop_error_t *error)
{
    model_t *m = ctx; mark(m, 'L'); m->registrations = o->registration_capacity;
    if (m->fault == 2) {
        *error = (vireo_event_loop_error_t){.stage = VIREO_EVENT_LOOP_STAGE_WAKE_CREATE, .system_errno = EMFILE};
        return m->failure_result;
    }
    return vireo_event_loop_create(o, owner, error);
}
static vireo_result_t model_loop_inspect(void *ctx, vireo_event_loop_t const *loop,
    vireo_event_loop_info_t *info)
{
    model_t *m = ctx; mark(m, 'I');
    if (m->fault == 3) return m->failure_result;
    vireo_result_t const r = vireo_event_loop_inspect(loop, info);
    if (r == VIREO_OK && m->fault == 4) --info->registration_capacity;
    return r;
}
static vireo_result_t model_loop_destroy(void *ctx, vireo_event_loop_t **loop,
    vireo_event_loop_error_t *error)
{
    model_t *m = ctx; mark(m, 'l'); ++m->loop_destroys;
    REQUIRE(vireo_event_loop_destroy(loop, error) == VIREO_OK);
    if (m->cleanup_io) {
        *error = (vireo_event_loop_error_t){.stage = VIREO_EVENT_LOOP_STAGE_DESTROY_EPOLL, .system_errno = EINTR};
        return VIREO_RESULT_IO;
    }
    return VIREO_OK;
}
static vireo_result_t model_pool_create(void *ctx, vireo_connection_pool_options_t const *o,
    vireo_connection_pool_t **owner, vireo_connection_pool_error_t *error)
{
    model_t *m = ctx; mark(m, 'P'); m->pool_capacity = o->capacity;
    if (m->fault == 5) {
        *error = (vireo_connection_pool_error_t){.stage = VIREO_CONNECTION_POOL_STAGE_CREATE_STORAGE};
        return m->failure_result;
    }
    return vireo_connection_pool_create(o, owner, error);
}
static vireo_result_t model_pool_inspect(void *ctx, vireo_connection_pool_t const *pool,
    vireo_connection_pool_info_t *info)
{
    model_t *m = ctx; mark(m, 'J');
    if (m->fault == 6) return m->failure_result;
    vireo_result_t const r = vireo_connection_pool_inspect(pool, info);
    if (r == VIREO_OK && m->fault == 7) info->capacity += 1;
    return r;
}
static vireo_result_t model_pool_destroy(void *ctx, vireo_connection_pool_t **pool,
    vireo_connection_pool_error_t *error)
{
    model_t *m = ctx; mark(m, 'p'); ++m->pool_destroys;
    return vireo_connection_pool_destroy(pool, error);
}
static vireo_tcp_server_ops_t model_ops(model_t *m)
{
    return (vireo_tcp_server_ops_t){m, model_allocate, model_free, model_loop_create,
        model_loop_inspect, model_loop_destroy, model_pool_create, model_pool_inspect, model_pool_destroy};
}

static void failed_model(unsigned fault, vireo_result_t returned, vireo_tcp_server_stage_t stage,
    char const *order, bool cleanup)
{
    model_t m = {.fault = fault, .failure_result = returned, .cleanup_io = cleanup};
    vireo_tcp_server_ops_t const ops = model_ops(&m);
    vireo_tcp_server_t *owner = NULL;
    vireo_tcp_server_error_t e;
    memset(&e, 0x5a, sizeof(e)); errno = EDOM;
    CHECK(vireo_tcp_server_create_with_auxiliary_ops(&options, 7, &ops, &owner, &e) == returned);
    CHECK(owner == NULL && errno == EDOM && e.stage == stage);
    CHECK(strcmp(m.order, order) == 0 && m.allocations == 1);
    CHECK(m.frees == (fault == 1 ? 0U : 1U));
    CHECK(e.cleanup_result == (cleanup ? VIREO_RESULT_IO : VIREO_OK));
    CHECK(e.cleanup_stage == (cleanup ? VIREO_TCP_SERVER_STAGE_DESTROY_LOOP : VIREO_TCP_SERVER_STAGE_NONE));
    if (cleanup) CHECK(e.cleanup_loop_error.system_errno == EINTR);
    if (fault == 2) CHECK(e.loop_error.system_errno == EMFILE);
    if (fault == 5) CHECK(e.pool_error.stage == VIREO_CONNECTION_POOL_STAGE_CREATE_STORAGE);
    CHECK(m.loop_destroys == (fault >= 3 ? 1U : 0U));
    CHECK(m.pool_destroys == (fault >= 6 ? 1U : 0U));
}
static void test_allocate_failure(void)
{ failed_model(1, VIREO_RESULT_NO_MEMORY, VIREO_TCP_SERVER_STAGE_ALLOCATE_CONTROL, "A", false); }
static void test_loop_create_io(void)
{ failed_model(2, VIREO_RESULT_IO, VIREO_TCP_SERVER_STAGE_CREATE_LOOP, "ALF", false); }
static void test_loop_create_memory(void)
{ failed_model(2, VIREO_RESULT_NO_MEMORY, VIREO_TCP_SERVER_STAGE_CREATE_LOOP, "ALF", false); }
static void test_loop_inspect_failure(void)
{ failed_model(3, VIREO_RESULT_IO, VIREO_TCP_SERVER_STAGE_INSPECT_LOOP, "ALIlF", false); }
static void test_loop_corrupt_capacity(void)
{ failed_model(4, VIREO_RESULT_INTERNAL, VIREO_TCP_SERVER_STAGE_INSPECT_LOOP, "ALIlF", false); }
static void test_pool_create_failure(void)
{ failed_model(5, VIREO_RESULT_NO_MEMORY, VIREO_TCP_SERVER_STAGE_CREATE_POOL, "ALIPlF", false); }
static void test_pool_inspect_failure(void)
{ failed_model(6, VIREO_RESULT_IO, VIREO_TCP_SERVER_STAGE_INSPECT_POOL, "ALIPJplF", false); }
static void test_pool_corrupt_capacity(void)
{ failed_model(7, VIREO_RESULT_INTERNAL, VIREO_TCP_SERVER_STAGE_INSPECT_POOL, "ALIPJplF", false); }
static void test_primary_and_cleanup_errors(void)
{ failed_model(5, VIREO_RESULT_NO_MEMORY, VIREO_TCP_SERVER_STAGE_CREATE_POOL, "ALIPlF", true); }

static void test_model_success_and_inspect_failure(void)
{
    model_t m = {0}; vireo_tcp_server_ops_t const ops = model_ops(&m);
    vireo_tcp_server_t *owner = NULL; vireo_tcp_server_error_t e;
    memset(&e, 0x5a, sizeof(e)); errno = EDOM;
    REQUIRE(vireo_tcp_server_create_with_auxiliary_ops(&options, 7, &ops, &owner, &e) == VIREO_OK);
    CHECK(errno == EDOM && error_zero(e) && m.registrations == 11 && m.pool_capacity == 3);
    CHECK(strcmp(m.order, "ALIPJ") == 0);
    vireo_tcp_server_info_t i;
    memset(&i, 0x5a, sizeof(i)); unsigned char saved[sizeof(i)]; memcpy(saved, &i, sizeof(i));
    m.fault = 3; m.failure_result = VIREO_RESULT_IO; errno = EDOM;
    CHECK(vireo_tcp_server_inspect(owner, &i) == VIREO_RESULT_IO);
    CHECK(errno == EDOM && memcmp(saved, &i, sizeof(i)) == 0);
    m.fault = 4;
    CHECK(vireo_tcp_server_inspect(owner, &i) == VIREO_RESULT_INTERNAL);
    CHECK(memcmp(saved, &i, sizeof(i)) == 0);
    m.fault = 0;
    REQUIRE(vireo_tcp_server_inspect(owner, &i) == VIREO_OK);
    CHECK(i.auxiliary_registration_capacity == 7);
    destroy(&owner);
    CHECK(m.frees == 1 && m.loop_destroys == 1 && m.pool_destroys == 1);
}

static void test_seam_invalid_and_consuming_destroy(void)
{
    model_t m = {0}; vireo_tcp_server_ops_t ops = model_ops(&m);
    vireo_tcp_server_t *owner = NULL; vireo_tcp_server_error_t e;
    CHECK(vireo_tcp_server_create_with_auxiliary_ops(&options, 1, NULL, &owner, &e) == VIREO_RESULT_INVALID_ARGUMENT);
    ops.inspect_loop = NULL;
    CHECK(vireo_tcp_server_create_with_auxiliary_ops(&options, 1, &ops, &owner, &e) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == NULL && m.allocations == 0 && error_zero(e));
    ops = model_ops(&m);
    CHECK(vireo_tcp_server_create_with_auxiliary_ops(&options, 0, &ops, &owner, &e) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == NULL && m.allocations == 0 && error_zero(e));
    REQUIRE(vireo_tcp_server_create_with_auxiliary_ops(&options, 1, &ops, &owner, &e) == VIREO_OK);
    m.cleanup_io = true; errno = EDOM;
    CHECK(vireo_tcp_server_destroy(&owner, &e) == VIREO_RESULT_IO);
    CHECK(owner == NULL && errno == EDOM && e.stage == VIREO_TCP_SERVER_STAGE_DESTROY_LOOP);
    CHECK(m.frees == 1 && m.loop_destroys == 1 && m.pool_destroys == 1);
}

typedef struct test_case {
    char const *name;
    void (*run)(void);
} test_case_t;

int main(void)
{
    test_case_t const cases[] = {
        {"旧入口与任意正辅助容量", test_old_and_auxiliary},
        {"总注册65536与真实fd不增加", test_total_maximum},
        {"基本拒绝与非空owner保持", test_basic_priority},
        {"原四项零值优先", test_original_zero_options},
        {"受检边界不回绕", test_checked_sum},
        {"原硬限检查优先", test_original_hard_limits_first},
        {"原客户上限保留与额外超限", test_old_maximum_and_extra_range},
        {"真实预算恰好及差一", test_exact_budget_and_short},
        {"停止与失败info保持", test_stop_and_inspect_holding},
        {"本层申请失败", test_allocate_failure},
        {"loop创建IO", test_loop_create_io},
        {"loop创建NO_MEMORY", test_loop_create_memory},
        {"loop观测失败逆序释放", test_loop_inspect_failure},
        {"loop容量副本异常", test_loop_corrupt_capacity},
        {"pool创建失败", test_pool_create_failure},
        {"pool观测失败逆序释放", test_pool_inspect_failure},
        {"pool容量副本异常", test_pool_corrupt_capacity},
        {"主错与清理错分别保留", test_primary_and_cleanup_errors},
        {"seam真实成功与info失败保持", test_model_success_and_inspect_failure},
        {"seam拒绝与消费型destroy IO", test_seam_invalid_and_consuming_destroy}
    };
    for (size_t n = 0; n < sizeof(cases) / sizeof(cases[0]); ++n) {
        unsigned const before = fd_count();
        cases[n].run(); CHECK(fd_count() == before);
        printf("group %zu: %s\n", n + 1, cases[n].name);
    }
    if (failures != 0) return EXIT_FAILURE;
    printf("server auxiliary capacity: %zu groups passed\n", sizeof(cases) / sizeof(cases[0]));
    return EXIT_SUCCESS;
}
