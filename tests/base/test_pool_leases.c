/*
 * PROJECT : VIREO
 * FILE    : test_pool_leases.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-02
 * BRIEF   : 此模块负责：
 * -- 通过公开租约验证借用、复用、失败保持及在用销毁
 * -- 在同一生产核心验证计数耗尽、地址复用与独立池并发身份
 * -- 用独立活动租约集合模型检查有界确定序列，不依赖空闲链布局
 */
#include <vireo/base/pool.h>
#include "base/pool_internal.h"

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

/* 真malloc backing由fixture拥有到cleanup；池回调归还只缓存以强制地址复用。 */
typedef struct cache {
    void *blocks[3];
    size_t sizes[3];
    bool live[3];
    size_t calls;
    size_t fail_at;
    size_t releases;
    size_t release_order[3];
    int error;
} cache_t;

static void *cache_allocate(void *context, size_t size) {
    cache_t *cache = context;
    errno = ENOMEM;
    if (cache->calls >= 3) {
        cache->error = 1;
        return NULL;
    }
    size_t index = cache->calls++;
    if (cache->calls == cache->fail_at) {
        return NULL;
    }
    if (cache->live[index] || (cache->blocks[index] != NULL && cache->sizes[index] != size)) {
        cache->error = 1;
        return NULL;
    }
    if (cache->blocks[index] == NULL) {
        cache->blocks[index] = malloc(size);
        cache->sizes[index] = size;
        if (cache->blocks[index] == NULL) {
            return NULL;
        }
        /* 测试自己初始化全部字节以供失败前后快照，不声称生产清零对象。 */
        memset(cache->blocks[index], 0xA5, size);
    }
    cache->live[index] = true;
    return cache->blocks[index];
}

static void cache_deallocate(void *context, void *memory) {
    cache_t *cache = context;
    errno = EIO;
    for (size_t i = 0; i < 3; ++i) {
        if (cache->live[i] && cache->blocks[i] == memory && cache->releases < 3) {
            cache->live[i] = false;
            cache->release_order[cache->releases++] = i;
            return;
        }
    }
    cache->error = 1;
}

static void cache_cleanup(cache_t *cache) {
    for (size_t i = 0; i < 3; ++i) {
        free(cache->blocks[i]);
        cache->blocks[i] = NULL;
    }
}

static vireo_pool_allocator_t cache_allocator(cache_t *cache) {
    return (vireo_pool_allocator_t){.context = cache,
        .allocate = cache_allocate, .deallocate = cache_deallocate};
}

static vireo_pool_options_t options_for(size_t capacity) {
    return (vireo_pool_options_t){.element_size = 13, .element_alignment = 8,
        .capacity = capacity, .max_memory_bytes = VIREO_POOL_MAX_MEMORY};
}

static int check_counts(vireo_pool_t *pool, size_t used, uint64_t generation) {
    vireo_pool_info_t info;
    errno = EACCES;
    CHECK(vireo_pool_inspect(pool, &info) == VIREO_OK && errno == EACCES);
    CHECK(info.pool_id != 0 && info.in_use_count == used);
    CHECK(info.available_count == info.layout.capacity - used);
    CHECK(info.last_generation == generation);
    return 0;
}

/* 输出快照含padding，指针输出使用存活的栈sentinel，不制造无效指针表示。 */
static int acquire_rejected(vireo_pool_t *pool, vireo_result_t expected) {
    vireo_pool_lease_t lease;
    memset(&lease, 0x5A, sizeof(lease));
    unsigned char before[sizeof(lease)];
    memcpy(before, &lease, sizeof(lease));
    unsigned char sentinel = 0;
    void *object = &sentinel;
    errno = EACCES;
    CHECK(vireo_pool_acquire(pool, &lease, &object) == expected && errno == EACCES);
    CHECK(object == &sentinel && memcmp(before, &lease, sizeof(lease)) == 0);
    return 0;
}

static int release_rejected(vireo_pool_t *pool, vireo_pool_lease_t lease,
                            vireo_result_t expected) {
    unsigned char before[sizeof(lease)];
    memcpy(before, &lease, sizeof(lease));
    errno = EACCES;
    CHECK(vireo_pool_release(pool, &lease) == expected && errno == EACCES);
    CHECK(memcmp(before, &lease, sizeof(lease)) == 0);
    return 0;
}

static int borrow_and_full_pool(void) {
    for (size_t alignment = 1; alignment <= _Alignof(max_align_t); alignment *= 2) {
        vireo_pool_options_t options = options_for(3);
        options.element_alignment = alignment;
        vireo_pool_t *pool = NULL;
        CHECK(vireo_pool_create(&options, &pool) == VIREO_OK);
        vireo_pool_lease_t leases[3];
        void *objects[3];
        for (size_t i = 0; i < 3; ++i) {
            errno = EACCES;
            CHECK(vireo_pool_acquire(pool, &leases[i], &objects[i]) == VIREO_OK);
            CHECK(errno == EACCES && (uintptr_t)objects[i] % alignment == 0);
            CHECK(leases[i].slot_index < 3 && leases[i].generation == i + 1);
            for (size_t j = 0; j < i; ++j) {
                CHECK(objects[j] != objects[i] && leases[j].slot_index != leases[i].slot_index);
            }
            memset(objects[i], (int)(i + 1), options.element_size);
        }
        CHECK(acquire_rejected(pool, VIREO_RESULT_BUSY) == 0);
        CHECK(check_counts(pool, 3, 3) == 0);
        vireo_pool_t *owner = pool;
        errno = EACCES;
        CHECK(vireo_pool_destroy(&pool) == VIREO_RESULT_BUSY && errno == EACCES && pool == owner);
        for (size_t i = 0; i < 3; ++i) {
            for (size_t j = 0; j < options.element_size; ++j) {
                CHECK(((unsigned char *)objects[i])[j] == (unsigned char)(i + 1));
            }
        }
        /* 非相邻顺序归还，其他活动对象保持；不依赖私有free链顺序。 */
        CHECK(vireo_pool_release(pool, &leases[1]) == VIREO_OK);
        objects[1] = NULL;
        CHECK(leases[1].pool_id == 0 && leases[1].slot_index == 0 && leases[1].generation == 0);
        CHECK(vireo_pool_release(pool, &leases[0]) == VIREO_OK);
        objects[0] = NULL;
        CHECK(((unsigned char *)objects[2])[12] == 3);
        CHECK(vireo_pool_release(pool, &leases[2]) == VIREO_OK && errno == EACCES);
        objects[2] = NULL;
        CHECK(check_counts(pool, 0, 3) == 0);
        CHECK(vireo_pool_destroy(&pool) == VIREO_OK && pool == NULL && errno == EACCES);
    }
    return 0;
}

static int reuse_and_stale_leases(void) {
    vireo_pool_t *pool = NULL;
    vireo_pool_options_t options = options_for(1);
    CHECK(vireo_pool_create(&options, &pool) == VIREO_OK);
    vireo_pool_lease_t first;
    void *object = NULL;
    CHECK(vireo_pool_acquire(pool, &first, &object) == VIREO_OK);
    uintptr_t address = (uintptr_t)object;
    vireo_pool_lease_t stale = first; /* 数值副本仍可保存，借用结束后不读旧指针。 */
    CHECK(vireo_pool_release(pool, &first) == VIREO_OK);
    object = NULL;
    CHECK(release_rejected(pool, first, VIREO_RESULT_NOT_FOUND) == 0);
    CHECK(release_rejected(pool, stale, VIREO_RESULT_NOT_FOUND) == 0);
    vireo_pool_lease_t current;
    CHECK(vireo_pool_acquire(pool, &current, &object) == VIREO_OK);
    CHECK((uintptr_t)object == address && current.slot_index == stale.slot_index);
    CHECK(current.generation > stale.generation && current.pool_id == stale.pool_id);
    memset(object, 0x7B, options.element_size);
    CHECK(release_rejected(pool, stale, VIREO_RESULT_NOT_FOUND) == 0);
    CHECK(check_counts(pool, 1, 2) == 0 && ((unsigned char *)object)[12] == 0x7B);
    vireo_pool_lease_t copy = current;
    CHECK(vireo_pool_release(pool, &copy) == VIREO_OK);
    object = NULL;
    CHECK(release_rejected(pool, current, VIREO_RESULT_NOT_FOUND) == 0);
    CHECK(vireo_pool_destroy(&pool) == VIREO_OK);
    return 0;
}

static int rejected_operations_preserve_all_resources(void) {
    cache_t cache = {0};
    vireo_pool_allocator_t allocator = cache_allocator(&cache);
    vireo_pool_options_t options = options_for(1);
    vireo_pool_t *pool = NULL;
    vireo_pool_t *other = NULL;
    CHECK(vireo_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_OK);
    CHECK(vireo_pool_create(&options, &other) == VIREO_OK);
    vireo_pool_lease_t lease;
    void *object = NULL;
    CHECK(vireo_pool_acquire(pool, &lease, &object) == VIREO_OK);
    memset(object, 0xC3, options.element_size);
    unsigned char *snapshots[3];
    for (size_t i = 0; i < 3; ++i) {
        snapshots[i] = malloc(cache.sizes[i]);
        CHECK(snapshots[i] != NULL);
        memcpy(snapshots[i], cache.blocks[i], cache.sizes[i]);
    }
    CHECK(acquire_rejected(pool, VIREO_RESULT_BUSY) == 0);
    CHECK(acquire_rejected(NULL, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    errno = EACCES;
    CHECK(vireo_pool_acquire(pool, NULL, &object) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_pool_acquire(pool, &lease, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_pool_release(pool, NULL) == VIREO_RESULT_INVALID_ARGUMENT && errno == EACCES);
    CHECK(release_rejected(NULL, lease, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    CHECK(release_rejected(other, lease, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    vireo_pool_lease_t invalid = lease;
    invalid.slot_index = SIZE_MAX;
    CHECK(release_rejected(pool, invalid, VIREO_RESULT_RANGE) == 0);
    invalid.generation = 0;
    CHECK(release_rejected(pool, invalid, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    invalid = lease;
    invalid.pool_id = 0;
    CHECK(release_rejected(pool, invalid, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    invalid = lease;
    ++invalid.generation;
    CHECK(release_rejected(pool, invalid, VIREO_RESULT_NOT_FOUND) == 0);
    CHECK(release_rejected(pool, (vireo_pool_lease_t){0}, VIREO_RESULT_NOT_FOUND) == 0);
    vireo_pool_t *owner = pool;
    CHECK(vireo_pool_destroy(&pool) == VIREO_RESULT_BUSY && pool == owner && errno == EACCES);
    CHECK(cache.calls == 3 && cache.releases == 0 && cache.error == 0);
    for (size_t i = 0; i < 3; ++i) {
        CHECK(memcmp(snapshots[i], cache.blocks[i], cache.sizes[i]) == 0);
        free(snapshots[i]);
    }
    CHECK(vireo_pool_release(pool, &lease) == VIREO_OK);
    object = NULL;
    CHECK(vireo_pool_destroy(&pool) == VIREO_OK && vireo_pool_destroy(&other) == VIREO_OK);
    CHECK(cache.releases == 3 && cache.error == 0);
    CHECK(cache.release_order[0] == 2 && cache.release_order[1] == 1 && cache.release_order[2] == 0);
    cache_cleanup(&cache);
    return 0;
}

static int recreated_pool_at_same_address(void) {
    cache_t cache = {0};
    vireo_pool_allocator_t allocator = cache_allocator(&cache);
    vireo_pool_options_t options = options_for(1);
    vireo_pool_t *pool = NULL;
    CHECK(vireo_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_OK);
    uintptr_t control_address = (uintptr_t)pool;
    vireo_pool_lease_t lease;
    void *object = NULL;
    CHECK(vireo_pool_acquire(pool, &lease, &object) == VIREO_OK);
    uintptr_t object_address = (uintptr_t)object;
    vireo_pool_lease_t old = lease;
    CHECK(vireo_pool_release(pool, &lease) == VIREO_OK);
    object = NULL;
    CHECK(vireo_pool_destroy(&pool) == VIREO_OK);
    cache.calls = 0;
    cache.releases = 0;
    CHECK(vireo_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_OK);
    CHECK((uintptr_t)pool == control_address);
    CHECK(vireo_pool_acquire(pool, &lease, &object) == VIREO_OK);
    CHECK((uintptr_t)object == object_address && lease.slot_index == old.slot_index);
    CHECK(lease.generation == old.generation && lease.pool_id != old.pool_id);
    CHECK(release_rejected(pool, old, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    CHECK(check_counts(pool, 1, 1) == 0);
    CHECK(vireo_pool_release(pool, &lease) == VIREO_OK);
    object = NULL;
    CHECK(vireo_pool_destroy(&pool) == VIREO_OK && cache.error == 0);
    cache_cleanup(&cache);
    return 0;
}

static int generation_exhaustion(void) {
    for (size_t capacity = 1; capacity <= 2; ++capacity) {
        cache_t cache = {0};
        vireo_pool_allocator_t allocator = cache_allocator(&cache);
        vireo_pool_options_t options = options_for(capacity);
        _Atomic uint64_t source;
        atomic_init(&source, 0);
        vireo_pool_t *pool = NULL;
        CHECK(vireo_pool_create_with_counters(&options, &allocator, &source,
            UINT64_MAX - 1, &pool) == VIREO_OK);
        vireo_pool_lease_t lease;
        void *object = NULL;
        CHECK(vireo_pool_acquire(pool, &lease, &object) == VIREO_OK);
        CHECK(lease.generation == UINT64_MAX);
        CHECK(acquire_rejected(pool, VIREO_RESULT_OVERFLOW) == 0); /* 满池/未满都耗尽优先。 */
        CHECK(check_counts(pool, 1, UINT64_MAX) == 0);
        errno = EACCES;
        CHECK(vireo_pool_destroy(&pool) == VIREO_RESULT_BUSY && errno == EACCES);
        CHECK(vireo_pool_release(pool, &lease) == VIREO_OK);
        object = NULL;
        CHECK(acquire_rejected(pool, VIREO_RESULT_OVERFLOW) == 0);
        CHECK(check_counts(pool, 0, UINT64_MAX) == 0);
        CHECK(cache.calls == 3 && cache.releases == 0);
        CHECK(vireo_pool_destroy(&pool) == VIREO_OK && errno == EACCES && cache.error == 0);
        cache_cleanup(&cache);
    }
    return 0;
}

static int identity_exhaustion_and_burned_failure(void) {
    cache_t cache = {0};
    vireo_pool_allocator_t allocator = cache_allocator(&cache);
    vireo_pool_options_t options = options_for(1);
    _Atomic uint64_t source;
    atomic_init(&source, UINT64_MAX - 1);
    vireo_pool_t *pool = NULL;
    CHECK(vireo_pool_create_with_counters(&options, &allocator, &source, 0, &pool) == VIREO_OK);
    vireo_pool_info_t info;
    CHECK(vireo_pool_inspect(pool, &info) == VIREO_OK && info.pool_id == UINT64_MAX);
    CHECK(vireo_pool_destroy(&pool) == VIREO_OK);
    cache.calls = 0;
    cache.releases = 0;
    errno = EACCES;
    CHECK(vireo_pool_create_with_counters(&options, &allocator, &source, 0, &pool) == VIREO_RESULT_OVERFLOW);
    CHECK(pool == NULL && cache.calls == 0 && errno == EACCES);
    CHECK(atomic_load(&source) == UINT64_MAX);
    CHECK(vireo_pool_create_with_counters(&options, &allocator, NULL, 0, &pool) == VIREO_RESULT_INVALID_ARGUMENT);
    cache_cleanup(&cache);
    for (size_t failure = 1; failure <= 3; ++failure) {
        cache = (cache_t){.fail_at = failure};
        atomic_init(&source, 41);
        CHECK(vireo_pool_create_with_counters(&options, &allocator, &source, 0, &pool) == VIREO_RESULT_NO_MEMORY);
        CHECK(pool == NULL && errno == EACCES && atomic_load(&source) == 42);
        CHECK(cache.calls == failure && cache.releases == failure - 1 && cache.error == 0);
        for (size_t i = 0; i < failure - 1; ++i) {
            CHECK(cache.release_order[i] == failure - 2 - i);
        }
        cache.calls = 0;
        cache.releases = 0;
        cache.fail_at = 0;
        CHECK(vireo_pool_create_with_counters(&options, &allocator, &source, 0, &pool) == VIREO_OK);
        CHECK(vireo_pool_inspect(pool, &info) == VIREO_OK && info.pool_id == 43);
        CHECK(vireo_pool_destroy(&pool) == VIREO_OK && errno == EACCES && cache.error == 0);
        cache_cleanup(&cache);
    }
    return 0;
}

static int metadata_arithmetic_priority(void) {
    cache_t cache = {0};
    vireo_pool_allocator_t allocator = cache_allocator(&cache);
    vireo_pool_options_t options = options_for(1);
    vireo_pool_t *pool = NULL;
    CHECK(vireo_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_OK);
    size_t metadata_unit = cache.sizes[2];
    size_t control_bytes = cache.sizes[0];
    CHECK(metadata_unit > 1);
    CHECK(vireo_pool_destroy(&pool) == VIREO_OK);
    cache_cleanup(&cache);
    cache = (cache_t){0};
    options.element_size = 1;
    options.element_alignment = 1;
    options.capacity = SIZE_MAX / metadata_unit + 1;
    options.max_memory_bytes = 1;
    errno = EACCES;
    CHECK(vireo_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_RESULT_OVERFLOW);
    CHECK(cache.calls == 0 && pool == NULL && errno == EACCES);
    options.capacity = 1;
    options.element_size = SIZE_MAX - control_bytes; /* 控制+storage可表示，再加metadata溢出。 */
    CHECK(vireo_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_RESULT_OVERFLOW);
    CHECK(cache.calls == 0 && pool == NULL && errno == EACCES);
    return 0;
}

/* 参考模型只保存活动租约集合与对象字节；不知道生产free链或下次槽号。 */
static int independent_active_set_model(void) {
    size_t const capacities[] = {1, 3, 7};
    size_t total_steps = 0;
    size_t expected_rejections = 0;
    for (size_t scenario = 0; scenario < 3; ++scenario) {
        size_t capacity = capacities[scenario];
        vireo_pool_options_t options = options_for(capacity);
        vireo_pool_t *pool = NULL;
        CHECK(vireo_pool_create(&options, &pool) == VIREO_OK);
        bool active[7] = {false};
        vireo_pool_lease_t leases[7] = {{0}};
        vireo_pool_lease_t stale[7] = {{0}};
        bool has_stale[7] = {false};
        void *objects[7] = {NULL};
        unsigned char values[7] = {0};
        uint32_t random = UINT32_C(0x517CC1B7) + (uint32_t)scenario;
        size_t used = 0;
        uint64_t generation = 0;
        for (size_t step = 0; step < 6000; ++step) {
            random = random * UINT32_C(1664525) + UINT32_C(1013904223); /* PRNG规定模2^32。 */
            size_t index = (size_t)(random >> 8) % capacity;
            unsigned operation = (unsigned)(random >> 24) % 5U;
            if (operation <= 1U) {
                if (used == capacity) {
                    CHECK(acquire_rejected(pool, VIREO_RESULT_BUSY) == 0);
                    ++expected_rejections;
                } else {
                    vireo_pool_lease_t lease;
                    void *object = NULL;
                    CHECK(vireo_pool_acquire(pool, &lease, &object) == VIREO_OK);
                    CHECK(lease.slot_index < capacity && !active[lease.slot_index]);
                    CHECK(lease.generation == ++generation);
                    index = lease.slot_index;
                    active[index] = true;
                    leases[index] = lease;
                    objects[index] = object;
                    values[index] = (unsigned char)(random & UINT32_C(0xFF));
                    memset(object, (int)values[index], options.element_size);
                    ++used;
                }
            } else if (operation == 2U && active[index]) {
                stale[index] = leases[index];
                has_stale[index] = true;
                CHECK(vireo_pool_release(pool, &leases[index]) == VIREO_OK);
                CHECK(leases[index].pool_id == 0 && leases[index].slot_index == 0 && leases[index].generation == 0);
                active[index] = false;
                objects[index] = NULL;
                --used;
            } else if (operation == 3U && has_stale[index]) {
                CHECK(release_rejected(pool, stale[index], VIREO_RESULT_NOT_FOUND) == 0);
                ++expected_rejections;
            } else if (operation == 4U && used != 0) {
                vireo_pool_t *owner = pool;
                errno = EACCES;
                CHECK(vireo_pool_destroy(&pool) == VIREO_RESULT_BUSY && pool == owner && errno == EACCES);
                ++expected_rejections;
            }
            CHECK(check_counts(pool, used, generation) == 0);
            for (size_t i = 0; i < capacity; ++i) {
                if (active[i]) {
                    for (size_t j = 0; j < options.element_size; ++j) {
                        CHECK(((unsigned char *)objects[i])[j] == values[i]);
                    }
                    for (size_t j = 0; j < i; ++j) {
                        CHECK(!active[j] || objects[i] != objects[j]);
                    }
                }
            }
            ++total_steps;
        }
        for (size_t i = 0; i < capacity; ++i) {
            if (active[i]) {
                CHECK(vireo_pool_release(pool, &leases[i]) == VIREO_OK);
                objects[i] = NULL;
            }
        }
        CHECK(check_counts(pool, 0, generation) == 0);
        CHECK(vireo_pool_destroy(&pool) == VIREO_OK && pool == NULL);
    }
    printf("pool model: %zu steps, %zu expected rejections, capacities 1/3/7\n",
        total_steps, expected_rejections);
    return 0;
}

#define WORKERS 4
#define CREATIONS 128

typedef struct worker {
    _Atomic size_t *ready;
    _Atomic bool *start;
    uint64_t identities[CREATIONS];
    int error;
} worker_t;

/* 门闩只协调真实线程入场，池均由各自线程独占；身份源由生产原子共享。 */
static void *create_worker(void *context) {
    worker_t *worker = context;
    (void)atomic_fetch_add_explicit(worker->ready, 1, memory_order_release);
    while (!atomic_load_explicit(worker->start, memory_order_acquire)) {
        (void)sched_yield();
    }
    for (size_t i = 0; i < CREATIONS; ++i) {
        vireo_pool_t *pool = NULL;
        vireo_pool_options_t options = options_for(1);
        vireo_pool_info_t info;
        vireo_pool_lease_t lease;
        void *object = NULL;
        if (vireo_pool_create(&options, &pool) != VIREO_OK ||
            vireo_pool_inspect(pool, &info) != VIREO_OK) {
            worker->error = 1;
            (void)vireo_pool_destroy(&pool);
            return NULL;
        }
        worker->identities[i] = info.pool_id;
        if (vireo_pool_acquire(pool, &lease, &object) != VIREO_OK) {
            worker->error = 1;
            (void)vireo_pool_destroy(&pool);
            return NULL;
        }
        memset(object, 0x2B, options.element_size);
        if (vireo_pool_release(pool, &lease) != VIREO_OK ||
            vireo_pool_destroy(&pool) != VIREO_OK) {
            worker->error = 1;
            return NULL;
        }
    }
    return NULL;
}

static int concurrent_independent_creation(void) {
    _Atomic size_t ready;
    _Atomic bool start;
    atomic_init(&ready, 0);
    atomic_init(&start, false);
    worker_t workers[WORKERS] = {{0}};
    pthread_t threads[WORKERS];
    size_t created = 0;
    for (; created < WORKERS; ++created) {
        workers[created].ready = &ready;
        workers[created].start = &start;
        if (pthread_create(&threads[created], NULL, create_worker, &workers[created]) != 0) {
            break;
        }
    }
    while (atomic_load_explicit(&ready, memory_order_acquire) != created) {
        (void)sched_yield();
    }
    atomic_store_explicit(&start, true, memory_order_release);
    int join_error = 0;
    for (size_t i = 0; i < created; ++i) {
        if (pthread_join(threads[i], NULL) != 0) {
            join_error = 1;
        }
    }
    CHECK(created == WORKERS && join_error == 0);
    uint64_t seen[WORKERS * CREATIONS];
    size_t count = 0;
    for (size_t i = 0; i < WORKERS; ++i) {
        CHECK(workers[i].error == 0);
        for (size_t j = 0; j < CREATIONS; ++j) {
            uint64_t id = workers[i].identities[j];
            CHECK(id != 0 && (j == 0 || id > workers[i].identities[j - 1]));
            for (size_t k = 0; k < count; ++k) {
                CHECK(id != seen[k]);
            }
            seen[count++] = id;
        }
    }
    printf("pool identity: %zu unique creations across %d threads\n", count, WORKERS);
    return 0;
}

int main(void) {
    struct { char const *name; int (*run)(void); } const groups[] = {
        {"borrow_and_full_pool", borrow_and_full_pool},
        {"reuse_and_stale_leases", reuse_and_stale_leases},
        {"rejected_operations_preserve_all_resources", rejected_operations_preserve_all_resources},
        {"recreated_pool_at_same_address", recreated_pool_at_same_address},
        {"generation_exhaustion", generation_exhaustion},
        {"identity_exhaustion_and_burned_failure", identity_exhaustion_and_burned_failure},
        {"metadata_arithmetic_priority", metadata_arithmetic_priority},
        {"independent_active_set_model", independent_active_set_model},
        {"concurrent_independent_creation", concurrent_independent_creation},
    };
    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); ++i) {
        if (groups[i].run() != 0) {
            fprintf(stderr, "FAIL pool leases: %s\n", groups[i].name);
            return EXIT_FAILURE;
        }
        printf("PASS pool leases: %s\n", groups[i].name);
    }
    printf("pool leases: %zu groups passed\n", sizeof(groups) / sizeof(groups[0]));
    return EXIT_SUCCESS;
}
