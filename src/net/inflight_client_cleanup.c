/* PROJECT : VIREO
 * FILE    : inflight_client_cleanup.c
 * BRIEF   : 固定表内一次有界历史客户清退
 */
#include "inflight_client_cleanup_internal.h"
#include "inflight_store_internal.h"
#include <errno.h>

/** 默认边界只调用公开取消primitive，无全局可变故障状态。 */
static vireo_result_t request_public(void *context, vireo_task_cancel_t *cancel) {
    (void)context;
    return vireo_task_cancel_request(cancel);
}
/** 只归还表份，其他独立持有者仍有效。 */
static vireo_result_t release_public(void *context, vireo_task_cancel_t **owner) {
    (void)context;
    return vireo_task_cancel_destroy(owner);
}
static vireo_inflight_client_cleanup_ops_t const default_ops = {NULL, request_public, release_public};

/** 发布完整局部报告、还原errno，不回滚已提交动作。 */
static vireo_result_t finish(vireo_result_t result, vireo_inflight_client_cleanup_report_t value,
    vireo_inflight_client_cleanup_report_t *out, int saved) {
    if (out != NULL) *out = value;
    errno = saved;
    return result;
}
/** 仅比较完整历史客户，不将协议sequence或slot单独当身份。 */
static bool belongs(vireo_task_metadata_t metadata, vireo_connection_pool_lease_t client) {
    return metadata.route.client_owner_id == client.pool_id &&
        metadata.route.client_slot_index == client.slot_index &&
        metadata.route.client_generation == client.generation;
}

vireo_result_t vireo_inflight_client_cleanup_with_ops(vireo_inflight_store_t *store,
    vireo_connection_pool_lease_t client, size_t begin_index, size_t max_slots,
    vireo_inflight_client_cleanup_report_t *out, vireo_inflight_client_cleanup_ops_t const *ops) {
    int const saved = errno;
    vireo_inflight_client_cleanup_report_t value = {0};
    if (store == NULL || out == NULL || max_slots == 0 || ops == NULL ||
        ops->request == NULL || ops->release == NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);
    if (max_slots > VIREO_INFLIGHT_STORE_MAX_CAPACITY || begin_index > store->capacity)
        return finish(VIREO_RESULT_RANGE, value, out, saved);
    if (client.pool_id == 0 && client.slot_index == 0 && client.generation == 0)
        return finish(VIREO_RESULT_NOT_FOUND, value, out, saved);
    if (client.pool_id == 0 || client.generation == 0)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);

    value.next_index = begin_index;
    if (store->count > store->capacity) {
        value.stage = VIREO_INFLIGHT_CLIENT_CLEANUP_CHECK_RECORD;
        value.stop_reason = VIREO_INFLIGHT_CLIENT_CLEANUP_ERROR;
        return finish(VIREO_RESULT_INTERNAL, value, out, saved);
    }
    while (value.next_index < store->capacity && value.scanned_slots < max_slots) {
        vireo_inflight_store_slot_t *slot = &store->slots[value.next_index];
        ++value.scanned_slots;
        if (slot->occupied && belongs(slot->metadata, client)) {
            ++value.matched_records;
            value.last_metadata = slot->metadata;
            value.last_cancel_requested = false;
            value.stop_reason = VIREO_INFLIGHT_CLIENT_CLEANUP_ERROR;
            value.stage = VIREO_INFLIGHT_CLIENT_CLEANUP_CHECK_RECORD;
            if (store->count == 0)
                return finish(VIREO_RESULT_INTERNAL, value, out, saved);
            if (slot->cancel != NULL) {
                value.stage = VIREO_INFLIGHT_CLIENT_CLEANUP_REQUEST_CANCEL;
                vireo_result_t const result = ops->request(ops->context, slot->cancel);
                if (result != VIREO_OK) return finish(result, value, out, saved);
                ++value.cancel_requests;
                value.last_cancel_requested = true;
            } else {
                ++value.without_cancel;
            }
            value.stage = VIREO_INFLIGHT_CLIENT_CLEANUP_RELEASE_CANCEL;
            vireo_result_t const result = ops->release(ops->context, &slot->cancel);
            if (result != VIREO_OK) return finish(result, value, out, saved);
            slot->metadata = (vireo_task_metadata_t){0};
            slot->occupied = false;
            --store->count;
            ++value.removed_records;
        }
        ++value.next_index;
    }
    value.stage = VIREO_INFLIGHT_CLIENT_CLEANUP_NONE;
    value.stop_reason = value.next_index == store->capacity ?
        VIREO_INFLIGHT_CLIENT_CLEANUP_COMPLETE : VIREO_INFLIGHT_CLIENT_CLEANUP_BUDGET;
    return finish(VIREO_OK, value, out, saved);
}

vireo_result_t vireo_inflight_store_cancel_client_batch(vireo_inflight_store_t *store,
    vireo_connection_pool_lease_t client, size_t begin_index, size_t max_slots,
    vireo_inflight_client_cleanup_report_t *out) {
    return vireo_inflight_client_cleanup_with_ops(store, client, begin_index, max_slots, out, &default_ops);
}
