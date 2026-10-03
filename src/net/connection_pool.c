/*
- PROJECT : VIREO
- FILE    : connection_pool.c
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 公开基础池上的空态资源、受检总预算与最后发布
- -- 阶段诊断、逆序回滚和基础池拒绝销毁时的所有权保持
- -- 连接 owner 转移、有效存储租约与消费型归还
 */
#include "connection_pool_internal.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <vireo/base/checked.h>
#include <vireo/net/connection.h>

/** 只为本层类型计算槽位大小；不获取或猜测 opaque connection 布局。 */
typedef struct connection_owner_slot {
    vireo_connection_t *owner;
} connection_owner_slot_t;

/** 索引独立于基础池资源；首项每项为空，未 acquire 的槽位字节不读取。 */
typedef struct connection_index_entry {
    connection_owner_slot_t *slot;
    vireo_pool_lease_t lease;
    size_t buffer_bytes;
} connection_index_entry_t;

struct vireo_connection_pool {
    vireo_pool_t *storage;
    connection_index_entry_t *index;
    vireo_pool_info_t storage_origin;
    vireo_connection_pool_info_t info;
    vireo_connection_pool_ops_t ops;
    vireo_connection_pool_connection_ops_t connection_ops;
    uint64_t last_generation;
};

/**
 * @brief 取得本层控制块或索引的独立内存
 *
 * @param[in] context
 *     未使用的借用上下文。
 * @param[in] bytes
 *     已受检的正申请字节数。
 *
 * @return malloc 取得的唯一 owner，失败为 NULL。
 *
 * @note 与 system_deallocate 配对，入口 errno 由公共边界恢复。
 */
static void *system_allocate(void *context, size_t bytes)
{
    (void)context;
    return malloc(bytes);
}

/**
 * @brief 释放本层独占内存
 *
 * @param[in] context
 *     未使用的借用上下文。
 * @param[in] memory
 *     system_allocate 取得的唯一 owner，调用后失效。
 *
 * @note 不拥有 context 或连接，errno 由公共边界恢复。
 */
static void system_deallocate(void *context, void *memory)
{
    (void)context;
    free(memory);
}

/**
 * @brief 在剩余预算内调用公开基础池构造
 *
 * @param[in] context
 *     未使用的借用上下文。
 * @param[in] options
 *     本层槽类型、容量及正剩余预算，调用期间借用。
 * @param[in,out] out_pool
 *     独立空 owner，成功取得基础池，失败保持。
 *
 * @return 原样返回基础池公开构造结果。
 *
 * @note 只依赖其公开合同，不使用私有布局。
 */
static vireo_result_t system_create_storage(void *context, vireo_pool_options_t const *options,
                                           vireo_pool_t **out_pool)
{
    (void)context;
    return vireo_pool_create(options, out_pool);
}

/**
 * @brief 取得基础池公开数值快照
 *
 * @param[in] context
 *     未使用的借用上下文。
 * @param[in] pool
 *     存活基础池，只在调用期间借用。
 * @param[out] out_info
 *     独立可写快照，失败保持。
 *
 * @return 原样返回基础池公开观测结果。
 *
 * @note 不获得槽位访问权或依赖基础池私有布局。
 */
static vireo_result_t system_inspect_storage(void *context, vireo_pool_t const *pool,
                                            vireo_pool_info_t *out_info)
{
    (void)context;
    return vireo_pool_inspect(pool, out_info);
}

/**
 * @brief 消费空基础池的唯一 owner
 *
 * @param[in] context
 *     未使用的借用上下文。
 * @param[in,out] pool
 *     独立基础池 owner 地址。
 *
 * @return 原样返回基础池公开销毁结果。
 *
 * @note 成功消费 owner，BUSY 时保持；没有隐式重试或连接析构。
 */
static vireo_result_t system_destroy_storage(void *context, vireo_pool_t **pool)
{
    (void)context;
    return vireo_pool_destroy(pool);
}

static vireo_connection_pool_ops_t const system_ops = {
    NULL, system_allocate, system_deallocate, system_create_storage,
    system_inspect_storage, system_destroy_storage
};

/**
 * @brief 只读查询连接的公开容量和生命周期
 *
 * @param[in] context
 *     未使用的借用上下文。
 * @param[in] connection
 *     存活连接，只在调用期间借用。
 * @param[out] out_info
 *     独立数值输出。
 *
 * @return 原样返回公开 inspect 结果。
 *
 * @note 不获得 fd 或 buffer 句柄。
 */
static vireo_result_t system_inspect_connection(void *context, vireo_connection_t const *connection,
                                               vireo_connection_info_t *out_info)
{
    (void)context;
    return vireo_connection_inspect(connection, out_info);
}

/**
 * @brief 调用公开连接销毁，保留消费型 IO 诊断
 *
 * @param[in] context
 *     未使用的借用上下文。
 * @param[in,out] owner
 *     独立连接 owner 地址，OK/IO 消费、BUSY 保持。
 * @param[out] error
 *     独立完整原诊断。
 *
 * @return 原样返回公开 destroy 结果。
 *
 * @note 不重试 close，不操作 loop 登记。
 */
static vireo_result_t system_destroy_connection(void *context, vireo_connection_t **owner,
                                               vireo_connection_error_t *error)
{
    (void)context;
    return vireo_connection_destroy(owner, error);
}

static vireo_connection_pool_connection_ops_t const system_connection_ops = {
    NULL, system_inspect_connection, system_destroy_connection
};

/**
 * @brief 统一提交诊断并恢复入口 errno
 *
 * @param[in] result
 *     已确定的返回分类。
 * @param[in] stage
 *     本层失败阶段或 NONE。
 * @param[out] error
 *     可空独立诊断，不保存地址。
 * @param[in] saved_errno
 *     最外层入口值。
 *
 * @return result 原值。
 *
 * @note 不操作资源或覆盖主错误分类。
 */
static vireo_result_t finish(vireo_result_t result, vireo_connection_pool_stage_t stage,
                              vireo_connection_pool_error_t *error, int saved_errno)
{
    if (error != NULL) {
        *error = (vireo_connection_pool_error_t){stage};
    }
    errno = saved_errno;
    return result;
}

/**
 * @brief 比较两个公开布局的字段
 *
 * @param[in] left
 *     非空有效布局，只读借用。
 * @param[in] right
 *     非空有效布局，只读借用。
 *
 * @retval true
 *     五个公开数值字段完全相同。
 * @retval false
 *     至少一个数值不同。
 *
 * @note 不比较 padding 或推导基础池私有 sizeof。
 */
static bool layout_equal(vireo_pool_layout_t const *left, vireo_pool_layout_t const *right)
{
    return left->element_size == right->element_size &&
           left->element_alignment == right->element_alignment &&
           left->capacity == right->capacity && left->slot_stride == right->slot_stride &&
           left->storage_bytes == right->storage_bytes;
}

/**
 * @brief 验证基础池固定申请和合法计数
 *
 * @param[in] info
 *     非空实际快照，只读借用。
 * @param[in] layout
 *     本层槽类型通过公开函数算出的布局。
 * @param[in] budget
 *     正剩余申请预算。
 *
 * @retval true
 *     布局、身份、计数及申请量满足公开合同。
 * @retval false
 *     发现数值合同异常。
 *
 * @note 短路比较先证明减法安全，不计算可回绕合计；不检查私有元数据布局。
 */
static bool storage_snapshot_valid(vireo_pool_info_t const *info,
                                    vireo_pool_layout_t const *layout, size_t budget)
{
    return layout_equal(&info->layout, layout) && info->max_memory_bytes == budget &&
           info->pool_id != 0 && info->in_use_count <= layout->capacity &&
           info->available_count == layout->capacity - info->in_use_count &&
           info->allocation_bytes <= budget &&
           info->metadata_bytes != 0 && info->allocation_bytes > layout->storage_bytes &&
           info->metadata_bytes < info->allocation_bytes - layout->storage_bytes;
}

/**
 * @brief 在完整资源表和连接表下构造，共享最后发布和失败回滚
 *
 * @param[in] options
 *     公共三项显式选项。
 * @param[in] ops
 *     本层资源完整借用表，成功按值复制。
 * @param[in] connection_ops
 *     连接完整借用表，成功按值复制。
 * @param[in,out] out_pool
 *     独立唯一空 owner。
 * @param[out] error
 *     可空资源阶段诊断。
 *
 * @return 公共构造结果，表不完整为 INVALID_ARGUMENT。
 *
 * @note 不调用连接操作；全部资源取得后才发布，保持入口 errno。
 */
static vireo_result_t create_impl(
    vireo_connection_pool_options_t const *options, vireo_connection_pool_ops_t const *ops,
    vireo_connection_pool_connection_ops_t const *connection_ops,
    vireo_connection_pool_t **out_pool, vireo_connection_pool_error_t *error)
{
    int const saved_errno = errno;
    vireo_result_t result;
    size_t index_bytes;
    size_t container_bytes;
    size_t total_bytes;
    vireo_pool_t *storage = NULL;
    vireo_pool_layout_t layout;
    vireo_pool_info_t storage_info;
    vireo_connection_pool_t *pool;
    connection_index_entry_t *index;
    vireo_connection_pool_stage_t stage = VIREO_CONNECTION_POOL_STAGE_NONE;

    if (options == NULL || out_pool == NULL || *out_pool != NULL || ops == NULL ||
        ops->allocate == NULL || ops->deallocate == NULL || ops->create_storage == NULL ||
        ops->inspect_storage == NULL || ops->destroy_storage == NULL ||
        connection_ops == NULL || connection_ops->inspect == NULL ||
        connection_ops->destroy == NULL || options->capacity == 0 ||
        options->max_memory_bytes == 0 || options->max_buffer_bytes == 0) {
        return finish(VIREO_RESULT_INVALID_ARGUMENT, stage, error, saved_errno);
    }
    result = vireo_checked_size_mul(options->capacity, sizeof(*index), &index_bytes);
    if (result == VIREO_OK) {
        result = vireo_checked_size_add(sizeof(*pool), index_bytes, &container_bytes);
    }
    if (result != VIREO_OK) {
        return finish(result, stage, error, saved_errno);
    }
    if (options->capacity > VIREO_CONNECTION_POOL_MAX_CAPACITY ||
        options->max_memory_bytes > VIREO_CONNECTION_POOL_MAX_MEMORY ||
        options->max_buffer_bytes > VIREO_CONNECTION_POOL_MAX_BUFFER_MEMORY ||
        container_bytes >= options->max_memory_bytes) {
        return finish(VIREO_RESULT_RANGE, stage, error, saved_errno);
    }
    vireo_pool_options_t const storage_options = {
        sizeof(connection_owner_slot_t), _Alignof(connection_owner_slot_t), options->capacity,
        options->max_memory_bytes - container_bytes
    };
    /* 数值布局使用公开受检入口，不能把基础池私有元数据大小塞进预算。 */
    result = vireo_pool_layout_compute(storage_options.element_size,
                                      storage_options.element_alignment, storage_options.capacity,
                                      SIZE_MAX, &layout);
    if (result != VIREO_OK) {
        return finish(result, stage, error, saved_errno);
    }
    stage = VIREO_CONNECTION_POOL_STAGE_CREATE_STORAGE;
    result = ops->create_storage(ops->context, &storage_options, &storage);
    if (result != VIREO_OK) {
        return finish(result, stage, error, saved_errno);
    }
    stage = VIREO_CONNECTION_POOL_STAGE_INSPECT_STORAGE;
    result = ops->inspect_storage(ops->context, storage, &storage_info);
    if (result == VIREO_OK &&
        (!storage_snapshot_valid(&storage_info, &layout, storage_options.max_memory_bytes) ||
         storage_info.in_use_count != 0 || storage_info.last_generation != 0)) {
        result = VIREO_RESULT_INTERNAL;
    }
    if (result == VIREO_OK) {
        result = vireo_checked_size_add(container_bytes, storage_info.allocation_bytes,
                                        &total_bytes);
        if (result != VIREO_OK || total_bytes > options->max_memory_bytes) {
            result = VIREO_RESULT_INTERNAL;
        }
    }
    if (result != VIREO_OK) {
        /* 已创建的真实空基础池按公共合同可销毁；首错优先，不修复违约 hook。 */
        (void)ops->destroy_storage(ops->context, &storage);
        return finish(result, stage, error, saved_errno);
    }
    stage = VIREO_CONNECTION_POOL_STAGE_ALLOCATE_CONTROL;
    pool = ops->allocate(ops->context, sizeof(*pool));
    if (pool == NULL) {
        (void)ops->destroy_storage(ops->context, &storage);
        return finish(VIREO_RESULT_NO_MEMORY, stage, error, saved_errno);
    }
    stage = VIREO_CONNECTION_POOL_STAGE_ALLOCATE_INDEX;
    index = ops->allocate(ops->context, index_bytes);
    if (index == NULL) {
        ops->deallocate(ops->context, pool);
        (void)ops->destroy_storage(ops->context, &storage);
        return finish(VIREO_RESULT_NO_MEMORY, stage, error, saved_errno);
    }
    for (size_t i = 0; i < options->capacity; ++i) {
        /* 类型化初始化保证 NULL 语义；不把 malloc 字节或全零位当指针值。 */
        index[i] = (connection_index_entry_t){NULL, {0, 0, 0}, 0};
    }
    *pool = (vireo_connection_pool_t){
        storage, index, storage_info,
        {options->capacity, 0, options->capacity, index_bytes, container_bytes,
         storage_info.allocation_bytes, total_bytes, options->max_memory_bytes,
         0, options->max_buffer_bytes},
        *ops, *connection_ops, 0
    };
    *out_pool = pool;
    return finish(VIREO_OK, VIREO_CONNECTION_POOL_STAGE_NONE, error, saved_errno);
}

vireo_result_t vireo_connection_pool_create_with_ops(
    vireo_connection_pool_options_t const *options, vireo_connection_pool_ops_t const *ops,
    vireo_connection_pool_t **out_pool, vireo_connection_pool_error_t *error)
{
    return create_impl(options, ops, &system_connection_ops, out_pool, error);
}

vireo_result_t vireo_connection_pool_create_with_connection_ops(
    vireo_connection_pool_options_t const *options,
    vireo_connection_pool_connection_ops_t const *connection_ops,
    vireo_connection_pool_t **out_pool, vireo_connection_pool_error_t *error)
{
    return create_impl(options, &system_ops, connection_ops, out_pool, error);
}

vireo_result_t vireo_connection_pool_create(vireo_connection_pool_options_t const *options,
                                           vireo_connection_pool_t **out_pool,
                                           vireo_connection_pool_error_t *error)
{
    return vireo_connection_pool_create_with_ops(options, &system_ops, out_pool, error);
}

vireo_result_t vireo_connection_pool_inspect(vireo_connection_pool_t const *pool,
                                            vireo_connection_pool_info_t *out_info)
{
    int const saved_errno = errno;
    vireo_pool_info_t storage_info;
    vireo_result_t result;
    if (pool == NULL || out_info == NULL) {
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_CONNECTION_POOL_STAGE_NONE,
                      NULL, saved_errno);
    }
    result = pool->ops.inspect_storage(pool->ops.context, pool->storage, &storage_info);
    if (result == VIREO_OK &&
        (!storage_snapshot_valid(&storage_info, &pool->storage_origin.layout,
                                 pool->storage_origin.max_memory_bytes) ||
         storage_info.pool_id != pool->storage_origin.pool_id ||
         storage_info.allocation_bytes != pool->storage_origin.allocation_bytes ||
         storage_info.metadata_bytes != pool->storage_origin.metadata_bytes ||
         storage_info.last_generation != pool->last_generation ||
         storage_info.in_use_count != pool->info.leased_slots ||
         storage_info.available_count != pool->info.available_slots ||
         pool->info.buffer_capacity_bytes > pool->info.max_buffer_bytes)) {
        result = VIREO_RESULT_INTERNAL;
    }
    if (result == VIREO_OK) {
        *out_info = pool->info;
    }
    return finish(result, VIREO_CONNECTION_POOL_STAGE_NONE, NULL, saved_errno);
}

vireo_result_t vireo_connection_pool_destroy(vireo_connection_pool_t **owner,
                                            vireo_connection_pool_error_t *error)
{
    int const saved_errno = errno;
    vireo_result_t result;
    if (owner == NULL) {
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_CONNECTION_POOL_STAGE_NONE,
                      error, saved_errno);
    }
    if (*owner == NULL) {
        return finish(VIREO_OK, VIREO_CONNECTION_POOL_STAGE_NONE, error, saved_errno);
    }
    vireo_connection_pool_t *pool = *owner;
    if (pool->info.leased_slots != 0) {
        return finish(VIREO_RESULT_BUSY, VIREO_CONNECTION_POOL_STAGE_NONE, error, saved_errno);
    }
    result = pool->ops.destroy_storage(pool->ops.context, &pool->storage);
    if (result != VIREO_OK) {
        return finish(result, VIREO_CONNECTION_POOL_STAGE_DESTROY_STORAGE, error, saved_errno);
    }
    /* 先确认基础池没有活租约，再释放本层；复制表避免释放控制块后访问它。 */
    vireo_connection_pool_ops_t const ops = pool->ops;
    ops.deallocate(ops.context, pool->index);
    ops.deallocate(ops.context, pool);
    *owner = NULL;
    return finish(VIREO_OK, VIREO_CONNECTION_POOL_STAGE_NONE, error, saved_errno);
}

/**
 * @brief 提交独立操作诊断，保持原连接错误与入口 errno
 *
 * @param[in] result
 *     已确定的本次分类。
 * @param[in] stage
 *     操作失败阶段或 NONE。
 * @param[in] connection_error
 *     原连接诊断数值，其他阶段为 NONE/0。
 * @param[out] error
 *     可空独立可写诊断。
 * @param[in] saved_errno
 *     最外层入口值。
 *
 * @return result 原值。
 *
 * @note 不隐式清理、重试或覆盖原 close 错误。
 */
static vireo_result_t operation_finish(vireo_result_t result,
                                       vireo_connection_pool_operation_stage_t stage,
                                       vireo_connection_error_t connection_error,
                                       vireo_connection_pool_operation_error_t *error,
                                       int saved_errno)
{
    if (error != NULL) {
        *error = (vireo_connection_pool_operation_error_t){stage, connection_error};
    }
    errno = saved_errno;
    return result;
}

/**
 * @brief 验证数值租约，身份和范围通过后才取得当前索引
 *
 * @param[in] pool
 *     非空存活容器，只读借用。
 * @param[in] lease
 *     调用者给出的按值记录。
 * @param[out] out_entry
 *     非空独立局部输出，成功借用当前索引；不转移其所有权。
 *
 * @return OK、INVALID_ARGUMENT、RANGE、NOT_FOUND 或 INTERNAL。
 *
 * @note 失败保持输出；这里只比较存储租约，不判定 fd/异步身份或执行网络操作。
 */
static vireo_result_t find_entry(vireo_connection_pool_t const *pool,
                                 vireo_connection_pool_lease_t lease,
                                 connection_index_entry_t **out_entry)
{
    if (lease.pool_id == 0 && lease.slot_index == 0 && lease.generation == 0) {
        return VIREO_RESULT_NOT_FOUND;
    }
    if (lease.pool_id == 0 || lease.generation == 0 ||
        lease.pool_id != pool->storage_origin.pool_id) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (lease.slot_index >= pool->info.capacity) {
        return VIREO_RESULT_RANGE;
    }
    connection_index_entry_t *entry = &pool->index[lease.slot_index];
    if (entry->slot == NULL || entry->lease.generation != lease.generation) {
        return VIREO_RESULT_NOT_FOUND;
    }
    if (entry->lease.pool_id != lease.pool_id || entry->lease.slot_index != lease.slot_index ||
        entry->slot->owner == NULL || entry->buffer_bytes == 0 ||
        pool->info.leased_slots == 0 || entry->buffer_bytes > pool->info.buffer_capacity_bytes) {
        return VIREO_RESULT_INTERNAL;
    }
    *out_entry = entry;
    return VIREO_OK;
}

vireo_result_t vireo_connection_pool_adopt(vireo_connection_pool_t *pool,
                                          vireo_connection_t **connection_owner,
                                          vireo_connection_pool_lease_t *out_lease,
                                          vireo_connection_pool_operation_error_t *error)
{
    int const saved_errno = errno;
    vireo_connection_error_t const no_connection_error = {VIREO_CONNECTION_STAGE_NONE, 0};
    vireo_connection_pool_operation_stage_t stage = VIREO_CONNECTION_POOL_OPERATION_NONE;
    vireo_result_t result;
    vireo_connection_info_t info;
    size_t buffer_bytes;
    size_t total_buffer_bytes;
    vireo_pool_lease_t storage_lease;
    void *object;
    if (pool == NULL || connection_owner == NULL || *connection_owner == NULL ||
        out_lease == NULL) {
        return operation_finish(VIREO_RESULT_INVALID_ARGUMENT, stage, no_connection_error,
                                error, saved_errno);
    }
    stage = VIREO_CONNECTION_POOL_OPERATION_INSPECT_CONNECTION;
    result = pool->connection_ops.inspect(pool->connection_ops.context, *connection_owner, &info);
    if (result != VIREO_OK) {
        return operation_finish(result, stage, no_connection_error, error, saved_errno);
    }
    result = vireo_checked_size_add(info.read_buffer.capacity, info.write_buffer.capacity,
                                    &buffer_bytes);
    if (result != VIREO_OK) {
        return operation_finish(result, stage, no_connection_error, error, saved_errno);
    }
    if (info.read_buffer.capacity == 0 || info.write_buffer.capacity == 0 ||
        buffer_bytes != info.buffer_capacity_bytes) {
        return operation_finish(VIREO_RESULT_INTERNAL, stage, no_connection_error,
                                error, saved_errno);
    }
    stage = VIREO_CONNECTION_POOL_OPERATION_NONE;
    if (info.loop_attached || info.callback_active ||
        info.close_state != VIREO_CONNECTION_CLOSE_OPEN) {
        return operation_finish(VIREO_RESULT_BUSY, stage, no_connection_error, error, saved_errno);
    }
    result = vireo_checked_size_add(pool->info.buffer_capacity_bytes, buffer_bytes,
                                    &total_buffer_bytes);
    if (result != VIREO_OK) {
        return operation_finish(result, stage, no_connection_error, error, saved_errno);
    }
    if (buffer_bytes > pool->info.max_buffer_bytes) {
        return operation_finish(VIREO_RESULT_RANGE, stage, no_connection_error, error, saved_errno);
    }
    if (total_buffer_bytes > pool->info.max_buffer_bytes) {
        return operation_finish(VIREO_RESULT_BUSY, stage, no_connection_error, error, saved_errno);
    }
    stage = VIREO_CONNECTION_POOL_OPERATION_ACQUIRE_SLOT;
    /* 租约/对象输出是独立局部存储，不能直接把基础池资源内字段作为输出。 */
    result = vireo_pool_acquire(pool->storage, &storage_lease, &object);
    if (result != VIREO_OK) {
        return operation_finish(result, stage, no_connection_error, error, saved_errno);
    }
    pool->last_generation = storage_lease.generation;
    if (storage_lease.pool_id != pool->storage_origin.pool_id ||
        storage_lease.slot_index >= pool->info.capacity || storage_lease.generation == 0 ||
        object == NULL) {
        return operation_finish(VIREO_RESULT_INTERNAL, stage, no_connection_error,
                                error, saved_errno);
    }
    connection_index_entry_t *entry = &pool->index[storage_lease.slot_index];
    if (entry->slot != NULL) {
        (void)vireo_pool_release(pool->storage, &storage_lease);
        return operation_finish(VIREO_RESULT_INTERNAL, stage, no_connection_error,
                                error, saved_errno);
    }
    connection_owner_slot_t *slot = object;
    *slot = (connection_owner_slot_t){*connection_owner};
    *entry = (connection_index_entry_t){slot, storage_lease, buffer_bytes};
    ++pool->info.leased_slots;
    --pool->info.available_slots;
    pool->info.buffer_capacity_bytes = total_buffer_bytes;
    *out_lease = (vireo_connection_pool_lease_t){
        storage_lease.pool_id, storage_lease.slot_index, storage_lease.generation
    };
    *connection_owner = NULL;
    return operation_finish(VIREO_OK, VIREO_CONNECTION_POOL_OPERATION_NONE, no_connection_error,
                            error, saved_errno);
}

vireo_result_t vireo_connection_pool_lookup(vireo_connection_pool_t const *pool,
                                           vireo_connection_pool_lease_t lease,
                                           vireo_connection_t **out_connection)
{
    int const saved_errno = errno;
    connection_index_entry_t *entry;
    vireo_result_t result;
    if (pool == NULL || out_connection == NULL) {
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_CONNECTION_POOL_STAGE_NONE,
                      NULL, saved_errno);
    }
    result = find_entry(pool, lease, &entry);
    if (result == VIREO_OK) {
        *out_connection = entry->slot->owner;
    }
    return finish(result, VIREO_CONNECTION_POOL_STAGE_NONE, NULL, saved_errno);
}

vireo_result_t vireo_connection_pool_release(vireo_connection_pool_t *pool,
                                            vireo_connection_pool_lease_t *lease,
                                            vireo_connection_pool_operation_error_t *error)
{
    int const saved_errno = errno;
    vireo_connection_error_t connection_error = {VIREO_CONNECTION_STAGE_NONE, 0};
    vireo_connection_pool_operation_stage_t stage = VIREO_CONNECTION_POOL_OPERATION_NONE;
    connection_index_entry_t *entry;
    vireo_result_t result;
    if (pool == NULL || lease == NULL) {
        return operation_finish(VIREO_RESULT_INVALID_ARGUMENT, stage, connection_error,
                                error, saved_errno);
    }
    result = find_entry(pool, *lease, &entry);
    if (result != VIREO_OK) {
        return operation_finish(result, stage, connection_error, error, saved_errno);
    }
    vireo_connection_t *connection_owner = entry->slot->owner;
    stage = VIREO_CONNECTION_POOL_OPERATION_DESTROY_CONNECTION;
    vireo_result_t const destroy_result = pool->connection_ops.destroy(
        pool->connection_ops.context, &connection_owner, &connection_error);
    if (destroy_result != VIREO_OK && destroy_result != VIREO_RESULT_IO) {
        return operation_finish(destroy_result, stage, connection_error, error, saved_errno);
    }
    if (connection_owner != NULL) {
        return operation_finish(VIREO_RESULT_INTERNAL, stage, connection_error, error, saved_errno);
    }
    /* 清理间接资源后才归还；事先复制需要的数值，release 成功后不再读取槽字节。 */
    entry->slot->owner = NULL;
    vireo_pool_lease_t storage_lease = entry->lease;
    size_t const buffer_bytes = entry->buffer_bytes;
    result = vireo_pool_release(pool->storage, &storage_lease);
    if (result != VIREO_OK) {
        return operation_finish(VIREO_RESULT_INTERNAL, VIREO_CONNECTION_POOL_OPERATION_RELEASE_SLOT,
                                connection_error, error, saved_errno);
    }
    *entry = (connection_index_entry_t){NULL, {0, 0, 0}, 0};
    --pool->info.leased_slots;
    ++pool->info.available_slots;
    pool->info.buffer_capacity_bytes -= buffer_bytes;
    lease->pool_id = 0;
    lease->slot_index = 0;
    lease->generation = 0;
    return operation_finish(destroy_result, destroy_result == VIREO_RESULT_IO ? stage :
                            VIREO_CONNECTION_POOL_OPERATION_NONE, connection_error,
                            error, saved_errno);
}
