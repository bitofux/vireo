/*
 * PROJECT : VIREO
 * FILE    : pool.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-02
 * BRIEF   : 此模块负责：
 * -- 复用 checked 证明槽位步长与总量可表示
 * -- 在检查与资源取得完成后发布固定容量池，失败逆序清理
 */

#include <vireo/base/pool.h>
#include <vireo/base/checked.h>
#include "pool_internal.h"

#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

typedef struct slot_metadata {
    size_t next_free;     /**< 空闲链索引；SIZE_MAX为链尾，在用时不读取。 */
    uint64_t generation;  /**< 最近发放序号；空闲槽仍保留数值，不授予权限。 */
    bool in_use;          /**< 真值恰表示一个未归还的当前租约。 */
} slot_metadata_t;

struct vireo_pool {
    vireo_pool_layout_t layout;       /**< 固定槽位布局；创建后不搬移。 */
    size_t allocation_bytes;         /**< 受检三点请求总量。 */
    size_t max_memory_bytes;         /**< 显式预算。 */
    size_t metadata_bytes;           /**< 独立元数据区申请量。 */
    void *storage;                   /**< 自有连续对象字节，不由管理链占用。 */
    slot_metadata_t *slots;          /**< 自有外部元数据，每槽唯一记录。 */
    size_t free_head;                /**< 空闲首索引，SIZE_MAX表示没有空闲。 */
    size_t in_use_count;             /**< 不超过capacity，与空闲数合计capacity。 */
    uint64_t pool_id;                /**< 非零且在库实例进程范围不复用。 */
    uint64_t last_generation;        /**< 全池发放序号，最大值后停止acquire。 */
    vireo_pool_allocator_t allocator; /**< 配对表按值保存，context只借用。 */
};

/* 独立创建共享的唯一状态；只管理数值身份，不发布对象或同步同池访问。 */
static _Atomic uint64_t last_pool_id = 0;

vireo_result_t vireo_pool_layout_compute(size_t element_size,
                                         size_t element_alignment,
                                         size_t capacity,
                                         size_t max_storage_bytes,
                                         vireo_pool_layout_t *out) {
    /* 零检测通过短路先于减一；这是池布局的专用限制，不收紧 checked。 */
    if (out == NULL || element_size == 0 || element_alignment == 0 ||
        capacity == 0 || max_storage_bytes == 0 ||
        (element_alignment & (element_alignment - 1)) != 0) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    vireo_pool_layout_t candidate = {
        .element_size = element_size,
        .element_alignment = element_alignment,
        .capacity = capacity
    };
    vireo_result_t result = vireo_checked_size_align_up(
        element_size, element_alignment, &candidate.slot_stride);
    if (result != VIREO_OK) {
        return result;
    }
    result = vireo_checked_size_mul(candidate.slot_stride, capacity,
                                    &candidate.storage_bytes);
    if (result != VIREO_OK) {
        return result;
    }
    if (candidate.storage_bytes > max_storage_bytes) {
        return VIREO_RESULT_RANGE;
    }

    *out = candidate;
    return VIREO_OK;
}

/**
 * @brief 将生产分配请求适配到 malloc
 * @param[in] context 不访问，生产传 NULL。
 * @param[in] size 已验证的正控制块、槽位区或元数据字节数。
 * @return 独立、max_align_t 对齐的自有存储，使用 deallocate_default 配对释放。
 * @retval NULL 未取得请求资源。
 * @note 不初始化字节；errno 可改变，由公共创建路径保存恢复。
 */
static void *allocate_default(void *context, size_t size) {
    (void)context;
    return malloc(size);
}

/**
 * @brief 消费配对 malloc 内存的所有权
 * @param[in] context 不访问，生产传 NULL。
 * @param[in] memory 本适配器取得且尚未释放的存储，调用后失效。
 * @note 无返回错误；不重入池、不提供安全擦除，公共销毁/回滚恢复 errno。
 */
static void deallocate_default(void *context, void *memory) {
    (void)context;
    free(memory);
}

/**
 * @brief 原子申请一次非零、不回绕的身份；失败分配不归还此数值
 * @param[in,out] source 已初始化的原子源，借用至返回，不保存指针。
 * @param[out] out 独立可写数值，成功提交，耗尽保持。
 * @retval VIREO_OK 以relaxed CAS独占下一身份。
 * @retval VIREO_RESULT_OVERFLOW 源已达UINT64_MAX。
 * @note 身份不需发布其他数据，relaxed仅保障唯一性；不保证lock-free或延迟。
 *     errno不读取/修改，生产源不重置；同池操作仍须外部同步。
 */
static vireo_result_t claim_identity(_Atomic uint64_t *source, uint64_t *out) {
    uint64_t observed = atomic_load_explicit(source, memory_order_relaxed);
    for (;;) {
        uint64_t next;
        vireo_result_t result = vireo_checked_u64_add(observed, 1, &next);
        if (result != VIREO_OK) {
            return result;
        }
        if (atomic_compare_exchange_weak_explicit(source, &observed, next,
                memory_order_relaxed, memory_order_relaxed)) {
            *out = next;
            return VIREO_OK;
        }
    }
}

vireo_result_t vireo_pool_create_with_counters(vireo_pool_options_t const *options,
    vireo_pool_allocator_t const *allocator, _Atomic uint64_t *identity_source,
    uint64_t initial_generation, vireo_pool_t **out_pool) {
    if (options == NULL || out_pool == NULL || *out_pool != NULL || allocator == NULL ||
        allocator->allocate == NULL || allocator->deallocate == NULL ||
        identity_source == NULL || options->max_memory_bytes == 0) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    vireo_pool_layout_t layout;
    /* 完整证明所有数值后才检查实际预算，不能用小预算遮盖溢出。 */
    vireo_result_t result = vireo_pool_layout_compute(options->element_size,
        options->element_alignment, options->capacity, SIZE_MAX, &layout);
    if (result != VIREO_OK) {
        return result;
    }
    size_t metadata_bytes;
    result = vireo_checked_size_mul(sizeof(slot_metadata_t), layout.capacity, &metadata_bytes);
    if (result != VIREO_OK) {
        return result;
    }
    size_t allocation_bytes;
    result = vireo_checked_size_add(sizeof(vireo_pool_t), layout.storage_bytes, &allocation_bytes);
    if (result != VIREO_OK) {
        return result;
    }
    result = vireo_checked_size_add(allocation_bytes, metadata_bytes, &allocation_bytes);
    if (result != VIREO_OK) {
        return result;
    }
    if (layout.element_alignment > _Alignof(max_align_t) ||
        options->max_memory_bytes > VIREO_POOL_MAX_MEMORY ||
        allocation_bytes > options->max_memory_bytes) {
        return VIREO_RESULT_RANGE;
    }

    size_t max_memory_bytes = options->max_memory_bytes;
    vireo_pool_allocator_t operations = *allocator;
    int saved_errno = errno;
    uint64_t identity;
    result = claim_identity(identity_source, &identity);
    if (result != VIREO_OK) {
        errno = saved_errno;
        return result;
    }
    vireo_pool_t *candidate = operations.allocate(operations.context, sizeof(*candidate));
    if (candidate == NULL) {
        errno = saved_errno;
        return VIREO_RESULT_NO_MEMORY;
    }
    void *storage = operations.allocate(operations.context, layout.storage_bytes);
    if (storage == NULL) {
        operations.deallocate(operations.context, candidate);
        errno = saved_errno;
        return VIREO_RESULT_NO_MEMORY;
    }
    slot_metadata_t *slots = operations.allocate(operations.context, metadata_bytes);
    if (slots == NULL) {
        operations.deallocate(operations.context, storage);
        operations.deallocate(operations.context, candidate);
        errno = saved_errno;
        return VIREO_RESULT_NO_MEMORY;
    }
    for (size_t i = 0; i < layout.capacity; ++i) {
        /* metadata_bytes可表示保证capacity<SIZE_MAX，i+1不回绕。 */
        slots[i] = (slot_metadata_t){.next_free = i + 1 == layout.capacity ? SIZE_MAX : i + 1,
            .generation = 0, .in_use = false};
    }
    *candidate = (vireo_pool_t){.layout = layout, .allocation_bytes = allocation_bytes,
        .max_memory_bytes = max_memory_bytes, .metadata_bytes = metadata_bytes,
        .storage = storage, .slots = slots, .free_head = 0, .in_use_count = 0,
        .pool_id = identity, .last_generation = initial_generation, .allocator = operations};
    *out_pool = candidate;
    errno = saved_errno;
    return VIREO_OK;
}

vireo_result_t vireo_pool_create_with_allocator(vireo_pool_options_t const *options,
    vireo_pool_allocator_t const *allocator, vireo_pool_t **out_pool) {
    return vireo_pool_create_with_counters(options, allocator, &last_pool_id, 0, out_pool);
}

vireo_result_t vireo_pool_create(vireo_pool_options_t const *options,
                                 vireo_pool_t **out_pool) {
    static vireo_pool_allocator_t const allocator = {
        .context = NULL, .allocate = allocate_default, .deallocate = deallocate_default,
    };
    return vireo_pool_create_with_allocator(options, &allocator, out_pool);
}

vireo_result_t vireo_pool_inspect(vireo_pool_t const *pool, vireo_pool_info_t *out_info) {
    if (pool == NULL || out_info == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    *out_info = (vireo_pool_info_t){.layout = pool->layout,
        .allocation_bytes = pool->allocation_bytes, .max_memory_bytes = pool->max_memory_bytes,
        .metadata_bytes = pool->metadata_bytes, .pool_id = pool->pool_id,
        .last_generation = pool->last_generation, .in_use_count = pool->in_use_count,
        .available_count = pool->layout.capacity - pool->in_use_count};
    return VIREO_OK;
}

vireo_result_t vireo_pool_acquire(vireo_pool_t *pool, vireo_pool_lease_t *out_lease,
                                  void **out_object) {
    if (pool == NULL || out_lease == NULL || out_object == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    uint64_t generation;
    vireo_result_t result = vireo_checked_u64_add(pool->last_generation, 1, &generation);
    if (result != VIREO_OK) {
        return result;
    }
    if (pool->free_head == SIZE_MAX) {
        return VIREO_RESULT_BUSY;
    }
    size_t index = pool->free_head;
    size_t offset;
    /* index<capacity且完整storage_bytes已受检；仍显式复用checked计算偏移。 */
    result = vireo_checked_size_mul(index, pool->layout.slot_stride, &offset);
    if (result != VIREO_OK) {
        return result;
    }
    void *object = (unsigned char *)pool->storage + offset;
    vireo_pool_lease_t lease = {.pool_id = pool->pool_id, .slot_index = index,
        .generation = generation};
    pool->free_head = pool->slots[index].next_free;
    pool->slots[index].generation = generation;
    pool->slots[index].in_use = true;
    pool->last_generation = generation;
    ++pool->in_use_count; /* 有空闲索引保证旧count<capacity。 */
    *out_lease = lease;
    *out_object = object;
    return VIREO_OK;
}

vireo_result_t vireo_pool_release(vireo_pool_t *pool, vireo_pool_lease_t *lease) {
    if (pool == NULL || lease == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (lease->pool_id == 0 && lease->slot_index == 0 && lease->generation == 0) {
        return VIREO_RESULT_NOT_FOUND;
    }
    if (lease->pool_id == 0 || lease->generation == 0 || lease->pool_id != pool->pool_id) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (lease->slot_index >= pool->layout.capacity) {
        return VIREO_RESULT_RANGE;
    }
    slot_metadata_t *slot = &pool->slots[lease->slot_index];
    if (!slot->in_use || slot->generation != lease->generation) {
        return VIREO_RESULT_NOT_FOUND;
    }
    slot->in_use = false;
    slot->next_free = pool->free_head;
    pool->free_head = lease->slot_index;
    --pool->in_use_count; /* 匹配在用槽保证旧count>0。 */
    lease->pool_id = 0;
    lease->slot_index = 0;
    lease->generation = 0;
    return VIREO_OK;
}

vireo_result_t vireo_pool_destroy(vireo_pool_t **pool) {
    if (pool == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (*pool == NULL) {
        return VIREO_OK;
    }
    vireo_pool_t *owned = *pool;
    if (owned->in_use_count != 0) {
        return VIREO_RESULT_BUSY;
    }
    int saved_errno = errno;
    /* 控制块释放前保存回调，释放后不读取 owned 的任何字段。 */
    vireo_pool_allocator_t operations = owned->allocator;
    operations.deallocate(operations.context, owned->slots);
    operations.deallocate(operations.context, owned->storage);
    operations.deallocate(operations.context, owned);
    *pool = NULL;
    errno = saved_errno;
    return VIREO_OK;
}
