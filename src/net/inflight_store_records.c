/*
 * PROJECT : VIREO
 * FILE    : inflight_store_records.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 公开准入核验、有界数值登记与历史取出
 */
#include "inflight_store_internal.h"
#include "inflight_cancel_internal.h"

#include <vireo/base/checked.h>

#include <errno.h>

/**
 * @brief
 *     发布独立诊断并恢复入口 errno，不修改主输出或表。
 *
 * @param[in] result
 *     此路径真实结果。
 * @param[in] detail
 *     此路径阶段，成功为 NONE。
 * @param[out] stage
 *     可空独立输出，只借至返回。
 * @param[in] saved_errno
 *     入口保存值。
 *
 * @return
 *     原 result。
 */
static vireo_result_t finish(vireo_result_t result, vireo_inflight_stage_t detail,
    vireo_inflight_stage_t *stage, int saved_errno) {
    if (stage != NULL) *stage = detail;
    errno = saved_errno;
    return result;
}

/**
 * @brief
 *     通过公开构造器检查完整 metadata，不复制其他核心的私有校验。
 *
 * @param[in] metadata
 *     已初始化按值输入。
 *
 * @return
 *     公开构造器结果，不发布局部构造值。
 */
static vireo_result_t validate(vireo_task_metadata_t metadata) {
    vireo_task_metadata_t value;
    return vireo_task_metadata_make(metadata.route, metadata.request_instance_id,
        metadata.operation, metadata.deadline_ns, &value);
}

/**
 * @brief
 *     比较完整客户数值，sequence 不参与客户身份。
 *
 * @param[in] left
 *     已校验有效路由。
 * @param[in] right
 *     表内有效路由。
 *
 * @return
 *     owner/slot/generation 三字段是否全部相等，不核验客户当前性。
 */
static bool same_client(vireo_task_route_t left, vireo_task_route_t right) {
    return left.client_owner_id == right.client_owner_id &&
        left.client_slot_index == right.client_slot_index &&
        left.client_generation == right.client_generation;
}

/**
 * @brief
 *     扫描 occupied 槽，以公开完整请求关系查找，不修改表。
 *
 * @param[in] store
 *     存活表，Reactor 独占访问。
 * @param[in] key
 *     已检查完整形态的请求键。
 * @param[out] out_index
 *     必需局部输出，成功为匹配槽；失败保持。
 *
 * @return
 *     找到为 OK，缺键 NOT_FOUND，公开比较错误原样返回。
 *
 * @note
 *     最多 capacity 次检查，不访问空槽 metadata。
 */
static vireo_result_t find_record(vireo_inflight_store_t const *store,
    vireo_task_metadata_t key, size_t *out_index) {
    for (size_t i = 0; i < store->capacity; ++i) {
        if (!store->slots[i].occupied) continue;
        bool same = false;
        vireo_result_t const result = vireo_task_metadata_same_request(
            key, store->slots[i].metadata, &same);
        if (result != VIREO_OK) return result;
        if (same) {
            *out_index = i;
            return VIREO_OK;
        }
    }
    return VIREO_RESULT_NOT_FOUND;
}

/**
 * @brief
 *     统一登记准入与提交；只有 limited 时检查本次客户限额。
 *
 * @param[in,out] store
 *     存活固定表，Reactor 独占访问。
 * @param[in] server
 *     当前客户公开资源根，短借。
 * @param[in] metadata
 *     已初始化按值输入，内部通过公开入口校验。
 * @param[in] limited
 *     是否使用显式客户限额；false 保持原 register 合同。
 * @param[in] max_client_requests
 *     limited 为 true 时必须正且不超过容量；false 时忽略。
 * @param[in] task
 *     可空；非空时 metadata 来自该存活 task，准入通过后取得可选关联。
 * @param[in] operations
 *     task 非空时必需完整短借操作表，不保存。
 * @param[out] stage
 *     可空独立诊断。
 *
 * @return
 *     沿两个公共登记入口的合同，失败不改表。
 *
 * @note
 *     查到空位仍扫描后续冲突；全部检查结束后才提交。
 */
static vireo_result_t register_impl(vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_task_metadata_t metadata,
    bool limited, size_t max_client_requests, vireo_task_t const *task,
    vireo_inflight_cancel_operations_t const *operations, vireo_inflight_stage_t *stage) {
    int const saved_errno = errno;
    if (store == NULL || server == NULL || (limited && max_client_requests == 0))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE, stage, saved_errno);
    vireo_result_t result = validate(metadata);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_CHECK_METADATA, stage, saved_errno);
    if (limited && max_client_requests > store->capacity)
        return finish(VIREO_RESULT_RANGE, VIREO_INFLIGHT_CHECK_RECORD, stage, saved_errno);

    vireo_connection_close_state_t state;
    vireo_inflight_stage_t detail = VIREO_INFLIGHT_NONE;
    result = vireo_inflight_check_client(server, metadata, &state, &detail);
    if (result != VIREO_OK) return finish(result, detail, stage, saved_errno);
    vireo_tcp_server_info_t info;
    result = vireo_tcp_server_inspect(server, &info);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_CHECK_SERVER, stage, saved_errno);
    if (info.stop_requested)
        return finish(VIREO_RESULT_CANCELLED, VIREO_INFLIGHT_CHECK_SERVER, stage, saved_errno);
    if (state != VIREO_CONNECTION_CLOSE_OPEN)
        return finish(VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_CLIENT, stage, saved_errno);

    size_t empty = store->capacity;
    size_t client_count = 0;
    for (size_t i = 0; i < store->capacity; ++i) {
        vireo_inflight_store_slot_t const *slot = &store->slots[i];
        if (!slot->occupied) {
            if (empty == store->capacity) empty = i;
            continue;
        }
        if (same_client(metadata.route, slot->metadata.route)) {
            if (metadata.route.request_sequence == slot->metadata.route.request_sequence ||
                metadata.request_instance_id == slot->metadata.request_instance_id)
                return finish(VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_RECORD, stage, saved_errno);
            if (limited) {
                result = vireo_checked_size_add(client_count, 1, &client_count);
                if (result != VIREO_OK)
                    return finish(result, VIREO_INFLIGHT_CHECK_RECORD, stage, saved_errno);
            }
        }
    }
    if (limited && client_count >= max_client_requests)
        return finish(VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_RECORD, stage, saved_errno);
    if (empty == store->capacity)
        return finish(VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_RECORD, stage, saved_errno);
    size_t next_count = 0;
    result = vireo_checked_size_add(store->count, 1, &next_count);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_CHECK_RECORD, stage, saved_errno);
    if (next_count > store->capacity)
        return finish(VIREO_RESULT_INTERNAL, VIREO_INFLIGHT_CHECK_RECORD, stage, saved_errno);

    vireo_task_cancel_t *cancel = NULL;
    if (task != NULL) {
        result = operations->retain_task(operations->context, task, &cancel);
        if (result != VIREO_OK && result != VIREO_RESULT_NOT_FOUND)
            return finish(result, VIREO_INFLIGHT_RETAIN_CANCEL, stage, saved_errno);
    }

    /* 引用已取得或确无关联；此后无可失败步骤，同 Reactor 一次逻辑提交。 */
    store->slots[empty].metadata = metadata;
    store->slots[empty].cancel = cancel;
    store->slots[empty].occupied = true;
    store->count = next_count;
    return finish(VIREO_OK, VIREO_INFLIGHT_NONE, stage, saved_errno);
}

vireo_result_t vireo_inflight_store_register(vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_task_metadata_t metadata,
    vireo_inflight_stage_t *stage) {
    return register_impl(store, server, metadata, false, 0, NULL, NULL, stage);
}

vireo_result_t vireo_inflight_store_register_limited(vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_task_metadata_t metadata,
    size_t max_client_requests, vireo_inflight_stage_t *stage) {
    return register_impl(store, server, metadata, true, max_client_requests, NULL, NULL, stage);
}

vireo_result_t vireo_inflight_store_count_client(vireo_inflight_store_t const *store,
    vireo_connection_pool_lease_t client, size_t *out_count,
    vireo_inflight_stage_t *stage) {
    int const saved_errno = errno;
    if (store == NULL || out_count == NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE, stage, saved_errno);
    if (client.pool_id == 0 && client.slot_index == 0 && client.generation == 0)
        return finish(VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_NONE, stage, saved_errno);

    /* 固定合法 sequence 仅适配公开 route 构造器；统计只比较客户三字段。 */
    vireo_task_route_t route;
    vireo_result_t result = vireo_task_route_make(client.pool_id, client.slot_index,
        client.generation, 1, &route);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_NONE, stage, saved_errno);
    size_t count = 0;
    for (size_t i = 0; i < store->capacity; ++i) {
        vireo_inflight_store_slot_t const *slot = &store->slots[i];
        if (!slot->occupied || !same_client(route, slot->metadata.route)) continue;
        result = vireo_checked_size_add(count, 1, &count);
        if (result != VIREO_OK)
            return finish(result, VIREO_INFLIGHT_CHECK_RECORD, stage, saved_errno);
    }
    *out_count = count;
    return finish(VIREO_OK, VIREO_INFLIGHT_NONE, stage, saved_errno);
}

vireo_result_t vireo_inflight_store_get(vireo_inflight_store_t const *store,
    vireo_task_metadata_t key, vireo_task_metadata_t *out_record,
    vireo_inflight_stage_t *stage) {
    int const saved_errno = errno;
    if (store == NULL || out_record == NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE, stage, saved_errno);
    vireo_result_t result = validate(key);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_CHECK_METADATA, stage, saved_errno);
    size_t index = 0;
    result = find_record(store, key, &index);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_CHECK_RECORD, stage, saved_errno);
    *out_record = store->slots[index].metadata;
    return finish(VIREO_OK, VIREO_INFLIGHT_NONE, stage, saved_errno);
}

vireo_result_t vireo_inflight_store_take(vireo_inflight_store_t *store,
    vireo_task_metadata_t key, vireo_task_metadata_t *out_record,
    vireo_inflight_stage_t *stage) {
    int const saved_errno = errno;
    if (store == NULL || out_record == NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE, stage, saved_errno);
    vireo_result_t result = validate(key);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_CHECK_METADATA, stage, saved_errno);
    size_t index = 0;
    result = find_record(store, key, &index);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_CHECK_RECORD, stage, saved_errno);
    if (store->count == 0 || store->count > store->capacity)
        return finish(VIREO_RESULT_INTERNAL, VIREO_INFLIGHT_CHECK_RECORD, stage, saved_errno);
    vireo_task_metadata_t const record = store->slots[index].metadata;
    result = vireo_task_cancel_destroy(&store->slots[index].cancel);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_RELEASE_CANCEL, stage, saved_errno);
    store->slots[index].metadata = (vireo_task_metadata_t){0};
    store->slots[index].occupied = false;
    --store->count;
    *out_record = record;
    return finish(VIREO_OK, VIREO_INFLIGHT_NONE, stage, saved_errno);
}

/**
 * @brief
 *     一次公开取得 task 的关联引用，不修改 task。
 *
 * @param[in] context
 *     标准适配不使用。
 * @param[in] task
 *     存活只借输入。
 * @param[out] out
 *     入口空引用 owner。
 *
 * @return
 *     原公开结果，包括无关联 NOT_FOUND 与耗尽 OVERFLOW。
 */
static vireo_result_t standard_retain_task(void *context, vireo_task_t const *task,
    vireo_task_cancel_t **out) {
    (void)context;
    return vireo_task_retain_cancel(task, out);
}

/**
 * @brief
 *     由表已有强引用保护，公开取得一份独立引用。
 *
 * @param[in] context
 *     标准适配不使用。
 * @param[in] cancel
 *     表持有且存活的状态。
 * @param[out] out
 *     caller 独占空引用 owner。
 *
 * @return
 *     原公开 retain 结果。
 */
static vireo_result_t standard_retain_cancel(void *context, vireo_task_cancel_t *cancel,
    vireo_task_cancel_t **out) {
    (void)context;
    return vireo_task_cancel_retain(cancel, out);
}

vireo_result_t vireo_inflight_store_register_task_limited_with_operations(
    vireo_inflight_store_t *store, vireo_tcp_server_t const *server,
    vireo_task_t const *task, size_t max_client_requests,
    vireo_inflight_cancel_operations_t const *operations, vireo_inflight_stage_t *stage) {
    int const saved_errno = errno;
    if (store == NULL || server == NULL || task == NULL || max_client_requests == 0 ||
        operations == NULL || operations->retain_task == NULL || operations->retain_cancel == NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE, stage, saved_errno);
    vireo_task_info_t info;
    vireo_result_t const result = vireo_task_inspect(task, &info);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_CHECK_METADATA, stage, saved_errno);
    return register_impl(store, server, info.metadata, true, max_client_requests, task, operations, stage);
}

vireo_result_t vireo_inflight_store_register_task_limited(vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_task_t const *task, size_t max_client_requests,
    vireo_inflight_stage_t *stage) {
    vireo_inflight_cancel_operations_t const operations = {NULL, standard_retain_task, standard_retain_cancel};
    return vireo_inflight_store_register_task_limited_with_operations(store, server, task,
        max_client_requests, &operations, stage);
}

vireo_result_t vireo_inflight_store_retain_cancel_with_operations(
    vireo_inflight_store_t const *store, vireo_task_metadata_t key,
    vireo_task_cancel_t **out_cancel, vireo_inflight_cancel_operations_t const *operations,
    vireo_inflight_stage_t *stage) {
    int const saved_errno = errno;
    if (store == NULL || out_cancel == NULL || *out_cancel != NULL || operations == NULL ||
        operations->retain_task == NULL || operations->retain_cancel == NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE, stage, saved_errno);
    vireo_result_t result = validate(key);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_CHECK_METADATA, stage, saved_errno);
    size_t index = 0;
    result = find_record(store, key, &index);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_CHECK_RECORD, stage, saved_errno);
    if (store->slots[index].cancel == NULL)
        return finish(VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_RETAIN_CANCEL, stage, saved_errno);
    result = operations->retain_cancel(operations->context, store->slots[index].cancel, out_cancel);
    return finish(result, result == VIREO_OK ? VIREO_INFLIGHT_NONE : VIREO_INFLIGHT_RETAIN_CANCEL,
        stage, saved_errno);
}

vireo_result_t vireo_inflight_store_retain_cancel(vireo_inflight_store_t const *store,
    vireo_task_metadata_t key, vireo_task_cancel_t **out_cancel, vireo_inflight_stage_t *stage) {
    vireo_inflight_cancel_operations_t const operations = {NULL, standard_retain_task, standard_retain_cancel};
    return vireo_inflight_store_retain_cancel_with_operations(store, key, out_cancel, &operations, stage);
}
