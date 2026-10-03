/*
- PROJECT : VIREO
- FILE    : test_event_loop_lifecycle.c
- AUTHOR  : bitofux
- DATE    : 2026-10-03
- BRIEF   : 此模块负责：
- -- 验证两层预算、完整发布、资源回滚与关闭报错消费
- -- 通过真实公共 epoll 和本层故障适配建立独立资源 oracle
 */
#define _POSIX_C_SOURCE 200809L
#include <vireo/net/event_loop.h>
#include "net/event_loop_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned failures;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
    ++failures; } } while (0)
#define REQUIRE(condition) do { if (!(condition)) { CHECK(condition); return; } } while (0)

typedef struct fixture {
    size_t allocations;
    size_t fail_allocation;
    size_t releases;
    size_t live;
    size_t sizes[3];
    void *blocks[3];
    unsigned creates;
    unsigned inspections;
    unsigned destroys;
    vireo_result_t create_result;
    vireo_epoll_error_t create_error;
    unsigned snapshot_fault;
    int close_error;
    int replacement;
    vireo_epoll_options_t received;
    vireo_epoll_info_t original_info;
    vireo_event_loop_t **owner;
    char order[16];
    size_t order_size;
} fixture_t;

static vireo_event_loop_options_t const default_options = {64, VIREO_EVENT_LOOP_MAX_MEMORY, 8};

/* 顺序日志只观察资源动作，不模拟内核集合或依赖私有控制块。 */
static void record(fixture_t *f, char step)
{
    CHECK(f->order_size + 1 < sizeof(f->order));
    if (f->order_size + 1 < sizeof(f->order)) {
        f->order[f->order_size++] = step;
        f->order[f->order_size] = '\0';
    }
}

/* 所有成功都真实 malloc，记录申请数和发布时点，失败不制造资源。 */
static void *allocate(void *context, size_t size)
{
    fixture_t *f = context;
    CHECK(f->owner != NULL && *f->owner == NULL);
    ++f->allocations;
    record(f, f->allocations == 1 ? 'a' : f->allocations == 2 ? 'b' : 'r');
    errno = ENOMEM;
    if (f->allocations == f->fail_allocation) {
        return NULL;
    }
    CHECK(f->allocations <= 3 && size > 0);
    if (f->allocations > 3) {
        return NULL;
    }
    void *memory = malloc(size);
    f->sizes[f->allocations - 1] = size;
    f->blocks[f->allocations - 1] = memory;
    if (memory != NULL) {
        ++f->live;
    }
    return memory;
}

/* 释放前识别块、移除记录，再物理 free；不读已经释放的控制块。 */
static void deallocate(void *context, void *memory)
{
    fixture_t *f = context;
    size_t index = 3;
    for (size_t i = 0; i < 3; ++i) {
        if (memory != NULL && f->blocks[i] == memory) {
            index = i;
        }
    }
    CHECK(index < 3);
    if (index < 3) {
        record(f, index == 0 ? 'A' : index == 1 ? 'B' : 'R');
        f->blocks[index] = NULL;
        --f->live;
        ++f->releases;
        free(memory);
    }
    errno = ERANGE; /* 清理不能污染原诊断或外层入口 errno。 */
}

/* 正常场景只走已封板公开接口；拒绝场景注入其公开失败后置，不碰旧 seam。 */
static vireo_result_t create_epoll(void *context, vireo_epoll_options_t const *options,
                                  vireo_epoll_t **owner, vireo_epoll_error_t *error)
{
    fixture_t *f = context;
    CHECK(f->owner != NULL && *f->owner == NULL && *owner == NULL);
    CHECK(f->live == 3 && f->allocations == 3);
    ++f->creates;
    record(f, 'e');
    f->received = *options;
    if (f->create_result != VIREO_OK) {
        *error = f->create_error;
        errno = EBUSY;
        return f->create_result;
    }
    return vireo_epoll_create(options, owner, error);
}

/* 先获得真实公共快照；异常注入只验证防御回滚，不声称正常依赖违反合同。 */
static vireo_result_t inspect_epoll(void *context, vireo_epoll_t const *epoll,
                                   vireo_epoll_info_t *info)
{
    fixture_t *f = context;
    CHECK(f->owner != NULL && *f->owner == NULL && f->live == 3);
    ++f->inspections;
    record(f, 'i');
    vireo_result_t result = vireo_epoll_inspect(epoll, info);
    CHECK(result == VIREO_OK);
    if (result != VIREO_OK) {
        return result;
    }
    f->original_info = *info;
    switch (f->snapshot_fault) {
    case 0: break;
    case 1: return VIREO_RESULT_INVALID_ARGUMENT;
    case 2: ++info->event_capacity; break;
    case 3: ++info->max_memory_bytes; break;
    case 4: info->events_bytes = 0; break;
    case 5: info->allocation_bytes = info->events_bytes; break;
    case 6: info->allocation_bytes = info->max_memory_bytes + 1; break;
    default: CHECK(0); break;
    }
    errno = EDOM;
    return VIREO_OK;
}

/* 实际 epoll 总先释放；再模拟“已消费但报告 IO”，保护新开的无关 fd。 */
static vireo_result_t destroy_epoll(void *context, vireo_epoll_t **owner,
                                   vireo_epoll_error_t *error)
{
    fixture_t *f = context;
    CHECK(owner != NULL && *owner != NULL && f->live == 3);
    ++f->destroys;
    record(f, 'c');
    vireo_result_t result = vireo_epoll_destroy(owner, error);
    CHECK(result == VIREO_OK && *owner == NULL);
    if (f->close_error != 0) {
        f->replacement = open("/dev/null", O_RDONLY | O_CLOEXEC);
        CHECK(f->replacement >= 0);
        *error = (vireo_epoll_error_t){VIREO_EPOLL_STAGE_CLOSE, f->close_error};
        errno = f->close_error;
        return VIREO_RESULT_IO;
    }
    errno = ENOSPC;
    return result;
}

static vireo_result_t add_epoll(void *context, vireo_epoll_t *epoll, int fd,
                                vireo_epoll_registration_t const *input, vireo_epoll_error_t *error)
{
    (void)context;
    return vireo_epoll_add(epoll, fd, input, error);
}

static vireo_result_t mod_epoll(void *context, vireo_epoll_t *epoll, int fd,
                                vireo_epoll_registration_t const *input, vireo_epoll_error_t *error)
{
    (void)context;
    return vireo_epoll_mod(epoll, fd, input, error);
}

static vireo_result_t del_epoll(void *context, vireo_epoll_t *epoll, int fd, vireo_epoll_error_t *error)
{
    (void)context;
    return vireo_epoll_del(epoll, fd, error);
}

/* 生命周期/登记回归仍只通过已封板公共 wait，当前测试不实际分发。 */
static vireo_result_t wait_epoll(void *context, vireo_epoll_t *epoll,
                                vireo_epoll_event_t *events, size_t capacity, int timeout_ms,
                                size_t *count, vireo_epoll_error_t *error)
{
    (void)context;
    return vireo_epoll_wait(epoll, timeout_ms, events, capacity, count, error);
}

static vireo_event_loop_ops_t make_ops(fixture_t *f, vireo_event_loop_t **owner)
{
    f->owner = owner;
    f->replacement = -1;
    vireo_event_loop_ops_t resources = vireo_event_loop_default_ops();
    resources.context = f;
    resources.allocate = allocate;
    resources.deallocate = deallocate;
    resources.create_epoll = create_epoll;
    resources.inspect_epoll = inspect_epoll;
    resources.destroy_epoll = destroy_epoll;
    resources.add_epoll = add_epoll;
    resources.mod_epoll = mod_epoll;
    resources.del_epoll = del_epoll;
    resources.wait_epoll = wait_epoll;
    return resources;
}

/* /proc 观察排除目录流自己的 fd，读取错误不计入正常基线。 */
static size_t fd_count(void)
{
    DIR *dir = opendir("/proc/self/fd");
    CHECK(dir != NULL);
    if (dir == NULL) {
        return SIZE_MAX;
    }
    int own = dirfd(dir);
    size_t count = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        char *end;
        long value = strtol(entry->d_name, &end, 10);
        if (*entry->d_name != '\0' && *end == '\0' && value >= 0 && value != own) {
            ++count;
        }
    }
    CHECK(errno == 0);
    CHECK(closedir(dir) == 0);
    return count;
}

static void check_clear(vireo_event_loop_error_t const *error)
{
    CHECK(error->stage == VIREO_EVENT_LOOP_STAGE_NONE);
    CHECK(error->epoll_error.stage == VIREO_EPOLL_STAGE_NONE);
    CHECK(error->epoll_error.system_errno == 0 && error->system_errno == 0);
}

static vireo_event_loop_error_t dirty_error(void)
{
    return (vireo_event_loop_error_t){
        VIREO_EVENT_LOOP_STAGE_DESTROY_EPOLL, {VIREO_EPOLL_STAGE_CLOSE, EIO}, EIO
    };
}

static void public_arguments(void)
{
    vireo_event_loop_t *owner = NULL;
    vireo_event_loop_error_t error = dirty_error();
    errno = EACCES;
    CHECK(vireo_event_loop_create(NULL, &owner, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == NULL && errno == EACCES);
    check_clear(&error);
    CHECK(vireo_event_loop_create(&default_options, NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_event_loop_destroy(NULL, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EACCES);
    check_clear(&error);
    CHECK(vireo_event_loop_destroy(&owner, &error) == VIREO_OK);
    CHECK(owner == NULL && errno == EACCES);
    check_clear(&error);
    REQUIRE(vireo_event_loop_create(&default_options, &owner, NULL) == VIREO_OK);
    vireo_event_loop_t *original = owner;
    CHECK(vireo_event_loop_create(&default_options, &owner, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == original && errno == EACCES);
    check_clear(&error);
    CHECK(vireo_event_loop_destroy(&owner, NULL) == VIREO_OK);
    CHECK(owner == NULL && errno == EACCES);
}

static void inspect_contract(void)
{
    vireo_event_loop_t *owner = NULL;
    vireo_event_loop_info_t info;
    unsigned char saved[sizeof(info)];
    memset(&info, 0xA5, sizeof(info));
    memcpy(saved, &info, sizeof(info));
    errno = EACCES;
    CHECK(vireo_event_loop_inspect(NULL, &info) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(saved, &info, sizeof(info)) == 0 && errno == EACCES);
    CHECK(vireo_event_loop_inspect(NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    REQUIRE(vireo_event_loop_create(&default_options, &owner, NULL) == VIREO_OK);
    CHECK(vireo_event_loop_inspect(owner, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_event_loop_inspect(owner, &info) == VIREO_OK);
    CHECK(info.event_capacity == 64 && info.events_bytes == 64 * sizeof(vireo_epoll_event_t));
    CHECK(info.loop_allocation_bytes > info.events_bytes + info.registrations_bytes);
    CHECK(info.registration_capacity == 8 && info.registered_count == 0 && info.available_count == 8);
    CHECK(info.registrations_bytes > 0 && info.loop_id != 0);
    CHECK(info.epoll_allocation_bytes > 0);
    CHECK(info.allocation_bytes == info.loop_allocation_bytes + info.epoll_allocation_bytes);
    CHECK(info.allocation_bytes <= info.max_memory_bytes);
    CHECK(info.max_memory_bytes == default_options.max_memory_bytes && errno == EACCES);
    printf("event loop budget: local=%zu, values=%zu, records=%zu, epoll=%zu, total=%zu\n",
           info.loop_allocation_bytes, info.events_bytes, info.registrations_bytes,
           info.epoll_allocation_bytes, info.allocation_bytes);
    vireo_event_loop_info_t copy = info;
    CHECK(vireo_event_loop_destroy(&owner, NULL) == VIREO_OK);
    CHECK(copy.event_capacity == 64 && copy.max_memory_bytes == VIREO_EVENT_LOOP_MAX_MEMORY);
}

static void capacity_boundaries(void)
{
    size_t const values[] = {0, 1, VIREO_EVENT_LOOP_MAX_EVENTS, VIREO_EVENT_LOOP_MAX_EVENTS + 1};
    vireo_result_t const expected[] = {
        VIREO_RESULT_INVALID_ARGUMENT, VIREO_OK, VIREO_OK, VIREO_RESULT_RANGE
    };
    size_t baseline = fd_count();
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        vireo_event_loop_t *owner = NULL;
        fixture_t f = {0};
        vireo_event_loop_ops_t ops = make_ops(&f, &owner);
        vireo_event_loop_options_t options = {values[i], VIREO_EVENT_LOOP_MAX_MEMORY, 8};
        vireo_event_loop_error_t error = dirty_error();
        errno = EACCES;
        CHECK(vireo_event_loop_create_with_ops(&options, &ops, &owner, &error) == expected[i]);
        CHECK(errno == EACCES);
        check_clear(&error);
        if (expected[i] == VIREO_OK) {
            vireo_event_loop_info_t info;
            REQUIRE(owner != NULL);
            CHECK(vireo_event_loop_inspect(owner, &info) == VIREO_OK);
            CHECK(info.event_capacity == values[i]);
            CHECK(info.events_bytes == values[i] * sizeof(vireo_epoll_event_t));
            CHECK(info.events_bytes == f.sizes[1]);
            CHECK(info.registrations_bytes == f.sizes[2]);
            CHECK(info.loop_allocation_bytes == f.sizes[0] + f.sizes[1] + f.sizes[2]);
            CHECK(info.epoll_allocation_bytes == f.original_info.allocation_bytes);
            CHECK(f.received.event_capacity == values[i]);
            CHECK(f.received.max_memory_bytes == options.max_memory_bytes - info.loop_allocation_bytes);
            CHECK(fd_count() == baseline + 3);
            errno = EACCES;
            CHECK(vireo_event_loop_destroy(&owner, &error) == VIREO_OK);
            CHECK(errno == EACCES && f.destroys == 1 && strcmp(f.order, "abreicRBA") == 0);
            check_clear(&error);
        } else {
            CHECK(owner == NULL && f.allocations == 0 && f.creates == 0);
        }
        CHECK(f.live == 0 && fd_count() == baseline);
    }
}

static void arithmetic_priority(void)
{
    size_t const values[] = {SIZE_MAX, SIZE_MAX / sizeof(vireo_epoll_event_t)};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        vireo_event_loop_t *owner = NULL;
        fixture_t f = {0};
        vireo_event_loop_ops_t ops = make_ops(&f, &owner);
        vireo_event_loop_options_t options = {values[i], 1, 8};
        vireo_event_loop_error_t error = dirty_error();
        errno = EACCES;
        CHECK(vireo_event_loop_create_with_ops(&options, &ops, &owner, &error) == VIREO_RESULT_OVERFLOW);
        CHECK(owner == NULL && f.allocations == 0 && f.creates == 0 && errno == EACCES);
        check_clear(&error);
        options.max_memory_bytes = 0;
        CHECK(vireo_event_loop_create_with_ops(&options, &ops, &owner, NULL) ==
              VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(owner == NULL && errno == EACCES);
    }
}

/* 精确需求从真实申请记录和公开快照获得，不使用任何内部 sizeof。 */
static void budget_boundaries(void)
{
    size_t baseline = fd_count();
    vireo_event_loop_t *owner = NULL;
    fixture_t probe = {0};
    vireo_event_loop_ops_t probe_ops = make_ops(&probe, &owner);
    REQUIRE(vireo_event_loop_create_with_ops(&default_options, &probe_ops, &owner, NULL) == VIREO_OK);
    vireo_event_loop_info_t info;
    REQUIRE(vireo_event_loop_inspect(owner, &info) == VIREO_OK);
    CHECK(info.loop_allocation_bytes == probe.sizes[0] + probe.sizes[1] + probe.sizes[2]);
    CHECK(info.epoll_allocation_bytes == probe.original_info.allocation_bytes);
    CHECK(vireo_event_loop_destroy(&owner, NULL) == VIREO_OK);
    size_t const budgets[] = {
        0, 1, info.loop_allocation_bytes - 1, info.loop_allocation_bytes,
        info.loop_allocation_bytes + 1, info.allocation_bytes - 1,
        info.allocation_bytes, info.allocation_bytes + 1,
        VIREO_EVENT_LOOP_MAX_MEMORY, VIREO_EVENT_LOOP_MAX_MEMORY + 1, SIZE_MAX
    };
    vireo_result_t const expected[] = {
        VIREO_RESULT_INVALID_ARGUMENT, VIREO_RESULT_RANGE, VIREO_RESULT_RANGE,
        VIREO_RESULT_RANGE, VIREO_RESULT_RANGE, VIREO_RESULT_RANGE,
        VIREO_OK, VIREO_OK, VIREO_OK, VIREO_RESULT_RANGE, VIREO_RESULT_RANGE
    };
    for (size_t i = 0; i < sizeof(budgets) / sizeof(budgets[0]); ++i) {
        fixture_t f = {0};
        vireo_event_loop_ops_t ops = make_ops(&f, &owner);
        vireo_event_loop_options_t options = {64, budgets[i], 8};
        vireo_event_loop_error_t error = dirty_error();
        errno = EACCES;
        CHECK(vireo_event_loop_create_with_ops(&options, &ops, &owner, &error) == expected[i]);
        CHECK(errno == EACCES);
        if (expected[i] == VIREO_OK) {
            vireo_event_loop_info_t actual;
            REQUIRE(owner != NULL);
            CHECK(vireo_event_loop_inspect(owner, &actual) == VIREO_OK);
            CHECK(actual.allocation_bytes == info.allocation_bytes);
            CHECK(actual.max_memory_bytes == budgets[i]);
            CHECK(actual.allocation_bytes <= actual.max_memory_bytes);
            check_clear(&error);
            CHECK(vireo_event_loop_destroy(&owner, NULL) == VIREO_OK);
        } else if (i == 4 || i == 5) {
            CHECK(owner == NULL && f.allocations == 3 && f.creates == 1);
            CHECK(f.inspections == 0 && f.destroys == 0 && f.releases == 3);
            CHECK(error.stage == VIREO_EVENT_LOOP_STAGE_CREATE_EPOLL);
            CHECK(error.epoll_error.stage == VIREO_EPOLL_STAGE_NONE);
            CHECK(error.epoll_error.system_errno == 0 && strcmp(f.order, "abreRBA") == 0);
        } else {
            CHECK(owner == NULL && f.allocations == 0 && f.creates == 0);
            check_clear(&error);
        }
        CHECK(owner == NULL && f.live == 0 && errno == EACCES);
        CHECK(fd_count() == baseline);
    }
    printf("event_loop budget: local=%zu epoll=%zu total=%zu bytes at capacity=64\n",
           info.loop_allocation_bytes, info.epoll_allocation_bytes, info.allocation_bytes);
}

static void invalid_ops(void)
{
    for (unsigned i = 0; i < 14; ++i) {
        vireo_event_loop_t *owner = NULL;
        fixture_t f = {0};
        vireo_event_loop_ops_t ops = make_ops(&f, &owner);
        vireo_event_loop_ops_t const *input = &ops;
        switch (i) {
        case 0: input = NULL; break;
        case 1: ops.allocate = NULL; break;
        case 2: ops.deallocate = NULL; break;
        case 3: ops.create_epoll = NULL; break;
        case 4: ops.inspect_epoll = NULL; break;
        case 5: ops.destroy_epoll = NULL; break;
        case 6: ops.add_epoll = NULL; break;
        case 7: ops.mod_epoll = NULL; break;
        case 8: ops.del_epoll = NULL; break;
        case 9: ops.wait_epoll = NULL; break;
        case 10: ops.create_pipe = NULL; break;
        case 11: ops.read_pipe = NULL; break;
        case 12: ops.write_pipe = NULL; break;
        case 13: ops.close_pipe = NULL; break;
        default: CHECK(0); break;
        }
        vireo_event_loop_error_t error = dirty_error();
        errno = EACCES;
        CHECK(vireo_event_loop_create_with_ops(&default_options, input, &owner, &error) ==
              VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(owner == NULL && f.allocations == 0 && f.creates == 0 && errno == EACCES);
        check_clear(&error);
    }
}

static void allocation_failures(void)
{
    size_t baseline = fd_count();
    for (size_t failure = 1; failure <= 3; ++failure) {
        for (unsigned diagnostic = 0; diagnostic < 2; ++diagnostic) {
            vireo_event_loop_t *owner = NULL;
            fixture_t f = {.fail_allocation = failure};
            vireo_event_loop_ops_t ops = make_ops(&f, &owner);
            vireo_event_loop_error_t error = dirty_error();
            errno = EACCES;
            CHECK(vireo_event_loop_create_with_ops(&default_options, &ops, &owner,
                  diagnostic != 0 ? &error : NULL) == VIREO_RESULT_NO_MEMORY);
            CHECK(owner == NULL && f.live == 0 && errno == EACCES);
            CHECK(f.allocations == failure && f.releases == failure - 1);
            CHECK(f.creates == 0 && f.inspections == 0 && f.destroys == 0);
            CHECK(strcmp(f.order, failure == 1 ? "a" : failure == 2 ? "abA" : "abrBA") == 0);
            if (diagnostic != 0) {
                CHECK(error.stage == (failure == 1 ? VIREO_EVENT_LOOP_STAGE_ALLOCATE_CONTROL :
                                                    failure == 2 ? VIREO_EVENT_LOOP_STAGE_ALLOCATE_EVENTS :
                                                    VIREO_EVENT_LOOP_STAGE_ALLOCATE_REGISTRATIONS));
                CHECK(error.epoll_error.stage == VIREO_EPOLL_STAGE_NONE);
                CHECK(error.epoll_error.system_errno == 0);
            }
            CHECK(fd_count() == baseline);
        }
    }
}

static void dependency_failures(void)
{
    struct cause { vireo_result_t result; vireo_epoll_stage_t stage; int number; };
    struct cause const causes[] = {
        {VIREO_RESULT_IO, VIREO_EPOLL_STAGE_CREATE, EMFILE},
        {VIREO_RESULT_IO, VIREO_EPOLL_STAGE_CREATE, ENFILE},
        {VIREO_RESULT_IO, VIREO_EPOLL_STAGE_CREATE, ENOMEM},
        {VIREO_RESULT_NO_MEMORY, VIREO_EPOLL_STAGE_ALLOCATE_CONTROL, 0},
        {VIREO_RESULT_NO_MEMORY, VIREO_EPOLL_STAGE_ALLOCATE_EVENTS, 0},
        {VIREO_RESULT_RANGE, VIREO_EPOLL_STAGE_NONE, 0}
    };
    size_t baseline = fd_count();
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        for (unsigned diagnostic = 0; diagnostic < 2; ++diagnostic) {
            vireo_event_loop_t *owner = NULL;
            fixture_t f = {.create_result = causes[i].result,
                           .create_error = {causes[i].stage, causes[i].number}};
            vireo_event_loop_ops_t ops = make_ops(&f, &owner);
            vireo_event_loop_error_t error = dirty_error();
            errno = EACCES;
            CHECK(vireo_event_loop_create_with_ops(&default_options, &ops, &owner,
                  diagnostic != 0 ? &error : NULL) == causes[i].result);
            CHECK(owner == NULL && f.live == 0 && errno == EACCES);
            CHECK(f.allocations == 3 && f.releases == 3 && f.creates == 1);
            CHECK(f.inspections == 0 && f.destroys == 0 && strcmp(f.order, "abreRBA") == 0);
            if (diagnostic != 0) {
                CHECK(error.stage == VIREO_EVENT_LOOP_STAGE_CREATE_EPOLL);
                CHECK(error.epoll_error.stage == causes[i].stage);
                CHECK(error.epoll_error.system_errno == causes[i].number);
            }
            CHECK(fd_count() == baseline);
        }
    }
}

/* 畸形快照与回滚 IO 是依赖合同异常注入；每次仍实际关闭真实 epoll。 */
static void snapshot_failures(void)
{
    size_t baseline = fd_count();
    for (unsigned fault = 1; fault <= 6; ++fault) {
        for (unsigned close_failure = 0; close_failure < 2; ++close_failure) {
            vireo_event_loop_t *owner = NULL;
            fixture_t f = {.snapshot_fault = fault,
                           .close_error = close_failure != 0 ? EINTR : 0};
            vireo_event_loop_ops_t ops = make_ops(&f, &owner);
            vireo_event_loop_error_t error = dirty_error();
            errno = EACCES;
            CHECK(vireo_event_loop_create_with_ops(&default_options, &ops, &owner, &error) ==
                  VIREO_RESULT_INTERNAL);
            CHECK(owner == NULL && f.live == 0 && errno == EACCES);
            CHECK(f.allocations == 3 && f.releases == 3 && f.creates == 1);
            CHECK(f.inspections == 1 && f.destroys == 1 && strcmp(f.order, "abreicRBA") == 0);
            CHECK(error.stage == VIREO_EVENT_LOOP_STAGE_INSPECT_EPOLL);
            CHECK(error.epoll_error.stage == (close_failure != 0 ? VIREO_EPOLL_STAGE_CLOSE :
                                                                   VIREO_EPOLL_STAGE_NONE));
            CHECK(error.epoll_error.system_errno == f.close_error);
            if (f.replacement >= 0) {
                CHECK(fcntl(f.replacement, F_GETFD) >= 0);
                CHECK(close(f.replacement) == 0);
            }
            CHECK(fd_count() == baseline);
        }
    }
}

static void destroy_failures(void)
{
    int const causes[] = {EINTR, EIO, EBADF};
    size_t baseline = fd_count();
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        for (unsigned diagnostic = 0; diagnostic < 2; ++diagnostic) {
            vireo_event_loop_t *owner = NULL;
            fixture_t f = {.close_error = causes[i]};
            vireo_event_loop_ops_t ops = make_ops(&f, &owner);
            vireo_event_loop_error_t error = dirty_error();
            REQUIRE(vireo_event_loop_create_with_ops(&default_options, &ops, &owner, &error) == VIREO_OK);
            check_clear(&error);
            errno = EACCES;
            CHECK(vireo_event_loop_destroy(&owner, diagnostic != 0 ? &error : NULL) == VIREO_RESULT_IO);
            CHECK(owner == NULL && f.live == 0 && errno == EACCES);
            CHECK(f.destroys == 1 && f.releases == 3 && strcmp(f.order, "abreicRBA") == 0);
            if (diagnostic != 0) {
                CHECK(error.stage == VIREO_EVENT_LOOP_STAGE_DESTROY_EPOLL);
                CHECK(error.epoll_error.stage == VIREO_EPOLL_STAGE_CLOSE);
                CHECK(error.epoll_error.system_errno == causes[i]);
            }
            REQUIRE(f.replacement >= 0);
            CHECK(fcntl(f.replacement, F_GETFD) >= 0);
            errno = EACCES;
            CHECK(vireo_event_loop_destroy(&owner, &error) == VIREO_OK);
            CHECK(owner == NULL && f.destroys == 1 && errno == EACCES);
            check_clear(&error);
            CHECK(fcntl(f.replacement, F_GETFD) >= 0);
            CHECK(close(f.replacement) == 0);
            CHECK(fd_count() == baseline);
        }
    }
}

static void copied_ops(void)
{
    vireo_event_loop_t *owner = NULL;
    fixture_t f = {0};
    vireo_event_loop_ops_t ops = make_ops(&f, &owner);
    REQUIRE(vireo_event_loop_create_with_ops(&default_options, &ops, &owner, NULL) == VIREO_OK);
    /* 输入表的地址没有被保留；上下文仍存活到配对清理。 */
    ops = (vireo_event_loop_ops_t){0};
    errno = EACCES;
    CHECK(vireo_event_loop_destroy(&owner, NULL) == VIREO_OK);
    CHECK(owner == NULL && f.live == 0 && f.destroys == 1 && errno == EACCES);
}

static void independent_instances(void)
{
    size_t baseline = fd_count();
    for (size_t round = 0; round < 128; ++round) {
        vireo_event_loop_t *first = NULL;
        vireo_event_loop_t *second = NULL;
        vireo_event_loop_options_t a = {1 + round % 7, VIREO_EVENT_LOOP_MAX_MEMORY, 8};
        vireo_event_loop_options_t b = {128 + round % 11, VIREO_EVENT_LOOP_MAX_MEMORY, 8};
        REQUIRE(vireo_event_loop_create(&a, &first, NULL) == VIREO_OK);
        REQUIRE(vireo_event_loop_create(&b, &second, NULL) == VIREO_OK);
        CHECK(first != second && fd_count() == baseline + 6);
        CHECK(vireo_event_loop_destroy(&first, NULL) == VIREO_OK);
        vireo_event_loop_info_t info;
        CHECK(vireo_event_loop_inspect(second, &info) == VIREO_OK);
        CHECK(info.event_capacity == b.event_capacity && fd_count() == baseline + 3);
        CHECK(vireo_event_loop_destroy(&second, NULL) == VIREO_OK);
        CHECK(fd_count() == baseline);
    }
}

/* 子进程在对象创建前 fork；fd 0 是真实自有 epoll，不使用继承的存活对象。 */
static void fd_zero(void)
{
    pid_t child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        failures = 0;
        CHECK(close(0) == 0 || errno == EBADF);
        vireo_event_loop_t *owner = NULL;
        errno = EACCES;
        CHECK(vireo_event_loop_create(&default_options, &owner, NULL) == VIREO_OK);
        CHECK(owner != NULL && errno == EACCES);
        int flags = fcntl(0, F_GETFD);
        CHECK(flags >= 0 && (flags & FD_CLOEXEC) != 0);
        errno = EACCES;
        CHECK(vireo_event_loop_destroy(&owner, NULL) == VIREO_OK);
        CHECK(owner == NULL && errno == EACCES);
        CHECK(fcntl(0, F_GETFD) == -1 && errno == EBADF);
        _exit(failures == 0 ? 0 : 1);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void external_resources(void)
{
    size_t baseline = fd_count();
    int channel[2];
    REQUIRE(pipe(channel) == 0);
    int status_flags[2] = {fcntl(channel[0], F_GETFL), fcntl(channel[1], F_GETFL)};
    int fd_flags[2] = {fcntl(channel[0], F_GETFD), fcntl(channel[1], F_GETFD)};
    vireo_event_loop_t *owner = NULL;
    REQUIRE(vireo_event_loop_create(&default_options, &owner, NULL) == VIREO_OK);
    CHECK(fd_count() == baseline + 5);
    CHECK(vireo_event_loop_destroy(&owner, NULL) == VIREO_OK);
    for (size_t i = 0; i < sizeof(channel) / sizeof(channel[0]); ++i) {
        CHECK(fcntl(channel[i], F_GETFL) == status_flags[i]);
        CHECK(fcntl(channel[i], F_GETFD) == fd_flags[i]);
    }
    char const input[] = "unrelated-fd";
    char output[sizeof(input)] = {0};
    CHECK(write(channel[1], input, sizeof(input)) == (ssize_t)sizeof(input));
    CHECK(read(channel[0], output, sizeof(output)) == (ssize_t)sizeof(output));
    CHECK(memcmp(input, output, sizeof(input)) == 0);
    CHECK(close(channel[1]) == 0 && close(channel[0]) == 0);
    CHECK(fd_count() == baseline);
}

int main(void)
{
    public_arguments();
    inspect_contract();
    capacity_boundaries();
    arithmetic_priority();
    budget_boundaries();
    invalid_ops();
    allocation_failures();
    dependency_failures();
    snapshot_failures();
    destroy_failures();
    copied_ops();
    independent_instances();
    fd_zero();
    external_resources();
    if (failures != 0) {
        fprintf(stderr, "test_event_loop_lifecycle: %u failures\n", failures);
        return EXIT_FAILURE;
    }
    puts("test_event_loop_lifecycle: 14 groups passed (128 dual instances)");
    return EXIT_SUCCESS;
}
