/*
 * PROJECT : VIREO
 * FILE    : client_deadline_store.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 固定容量数值记录保存、按完整身份查询及显式转出
 * -- 只依赖已采用公开合同，保持资源、输出与 errno 的既有边界
 */
#include <errno.h>
#include <stdlib.h>
#include <vireo/base/checked.h>
#include "client_deadline_store_internal.h"

/**
 * @brief
 *     统一发布本次独立诊断并恢复入口 errno。
 *
 * @param[in] result
 *     本次原结果分类，按值返回，不重试或补偿。
 * @param[in] saved_errno
 *     入口 errno 的保存值，恢复调用线程该值。
 *
 * @return
 *     原样返回 result；不追加可失败操作。
 *
 * @note
 *     不修改主输出、资源或业务进度，不进行后置观测。
 */
static vireo_result_t finish(vireo_result_t result, int saved_errno) {
    errno = saved_errno;
    return result;
}

/**
 * @brief
 *     发布保存操作的可空独立阶段并恢复入口 errno。
 *
 * @param[in] result
 *     本次原分类，按值透传。
 * @param[in] stage
 *     本次核验阶段，成功为 NONE。
 * @param[out] out_stage
 *     可空独立阶段地址；非空时覆盖。
 * @param[in] saved_errno
 *     调用线程入口 errno 的保存值。
 *
 * @return
 *     原样返回 result，不修改表或外部资源。
 */
static vireo_result_t finish_save(vireo_result_t result, vireo_client_deadline_stage_t stage,
                                  vireo_client_deadline_stage_t *out_stage, int saved_errno) {
    if (out_stage != NULL) {
        *out_stage = stage;
    }
    return finish(result, saved_errno);
}

/**
 * @brief
 *     比较完整 timer 数值键的三个身份字段。
 *
 * @param[in] a
 *     已由上层形态检查的按值键或表中逻辑空键。
 * @param[in] b
 *     已由上层形态检查的按值键。
 *
 * @return
 *     三个逻辑字段相等返回 true，否则 false。
 *
 * @note
 *     不比较 padding，不核验当前性或授权，不修改 errno。
 */
static bool same_timer(vireo_timer_handle_t a, vireo_timer_handle_t b) {
    return a.owner_id == b.owner_id && a.slot_index == b.slot_index && a.generation == b.generation;
}

/**
 * @brief
 *     检查绑定双方的完整形态及逻辑空身份。
 *
 * @param[in] binding
 *     按值记录，不访问 server／wheel 或表内部。
 *
 * @return
 *     完整非空返回 OK；全部逻辑零 NOT_FOUND；半空／畸形 INVALID_ARGUMENT；依赖错误原样返回。
 *
 * @note
 *     不修改记录、资源或 errno；不确认所属 owner、容量或活跃性。
 */
static vireo_result_t binding_shape(vireo_client_deadline_binding_t binding) {
    bool const client_empty = binding.client.pool_id == 0 && binding.client.slot_index == 0 &&
                              binding.client.generation == 0;
    bool timer_empty = false;
    if (!client_empty && (binding.client.pool_id == 0 || binding.client.generation == 0)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    vireo_result_t const result = vireo_timer_handle_is_empty(binding.timer, &timer_empty);
    if (result != VIREO_OK) {
        return result;
    }
    if (client_empty != timer_empty) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    return client_empty ? VIREO_RESULT_NOT_FOUND : VIREO_OK;
}

/**
 * @brief
 *     为本层单块控制及记录数组请求标准独占内存。
 *
 * @param[in] bytes
 *     经过公开构造路径受检且为正的请求字节数。
 * @param[in,out] context
 *     生产入口传 NULL；此适配忽略该地址，不保存或解引用。
 *
 * @return
 *     malloc 成功的正确对齐内存，或 NULL；外层负责报告 NO_MEMORY。
 *
 * @note
 *     成功所有权交构造路径，最终标准 free；可能改变 errno，由外层恢复。
 */
static void *standard_allocate(size_t bytes, void *context) {
    (void)context;
    return malloc(bytes);
}

vireo_result_t vireo_client_deadline_store_create_runtime(
    vireo_client_deadline_store_options_t const *options, vireo_client_deadline_store_t **out_store,
    void *(*allocate)(size_t bytes, void *context), void *context) {
    int const saved_errno = errno;
    if (options == NULL || out_store == NULL || *out_store != NULL || allocate == NULL ||
        options->capacity == 0 || options->max_memory_bytes == 0) {
        return finish(VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    size_t array_bytes = 0;
    size_t total = 0;
    vireo_result_t result = vireo_checked_size_mul(
        options->capacity, sizeof(vireo_client_deadline_binding_t), &array_bytes);
    if (result == VIREO_OK) {
        result = vireo_checked_size_add(sizeof(vireo_client_deadline_store_t), array_bytes, &total);
    }
    if (result != VIREO_OK) {
        return finish(result, saved_errno);
    }
    if (options->capacity > VIREO_CLIENT_DEADLINE_STORE_MAX_CAPACITY ||
        options->max_memory_bytes > VIREO_CLIENT_DEADLINE_STORE_MAX_MEMORY ||
        total > options->max_memory_bytes) {
        return finish(VIREO_RESULT_RANGE, saved_errno);
    }
    vireo_client_deadline_store_t *owned = allocate(total, context);
    if (owned == NULL) {
        return finish(VIREO_RESULT_NO_MEMORY, saved_errno);
    }
    owned->capacity = options->capacity;
    owned->count = 0;
    owned->allocation_bytes = total;
    owned->max_memory_bytes = options->max_memory_bytes;
    for (size_t i = 0; i < owned->capacity; ++i) {
        owned->records[i] = (vireo_client_deadline_binding_t){0};
    }
    *out_store = owned;
    return finish(VIREO_OK, saved_errno);
}

vireo_result_t vireo_client_deadline_store_create(
    vireo_client_deadline_store_options_t const *options,
    vireo_client_deadline_store_t **out_store) {
    return vireo_client_deadline_store_create_runtime(options, out_store, standard_allocate, NULL);
}

vireo_result_t vireo_client_deadline_store_inspect(vireo_client_deadline_store_t const *store,
                                                   vireo_client_deadline_store_info_t *out_info) {
    int const saved_errno = errno;
    if (store == NULL || out_info == NULL) {
        return finish(VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    *out_info = (vireo_client_deadline_store_info_t){
        store->capacity, store->count, store->allocation_bytes, store->max_memory_bytes};
    return finish(VIREO_OK, saved_errno);
}

vireo_result_t vireo_client_deadline_store_save(vireo_client_deadline_store_t *store,
                                                vireo_tcp_server_t const *server,
                                                vireo_timer_wheel_t const *wheel,
                                                vireo_client_deadline_binding_t binding,
                                                vireo_client_deadline_stage_t *out_stage) {
    int const saved_errno = errno;
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_NONE;
    if (store == NULL || server == NULL || wheel == NULL) {
        return finish_save(VIREO_RESULT_INVALID_ARGUMENT, stage, out_stage, saved_errno);
    }
    vireo_result_t result = binding_shape(binding);
    if (result != VIREO_OK) {
        return finish_save(result, stage, out_stage, saved_errno);
    }
    size_t free_index = store->capacity;
    for (size_t i = 0; i < store->capacity; ++i) {
        if (same_timer(store->records[i].timer, binding.timer)) {
            return finish_save(VIREO_RESULT_BUSY, stage, out_stage, saved_errno);
        }
        if (free_index == store->capacity && store->records[i].timer.owner_id == 0) {
            free_index = i;
        }
    }
    if (free_index == store->capacity) {
        return finish_save(VIREO_RESULT_BUSY, stage, out_stage, saved_errno);
    }
    vireo_client_deadline_binding_t verified;
    result =
        vireo_client_deadline_make(server, wheel, binding.client, binding.timer, &verified, &stage);
    if (result != VIREO_OK) {
        return finish_save(result, stage, out_stage, saved_errno);
    }
    /* count < capacity <= 65536；当前双方核验后只有不可失败数值提交。 */
    store->records[free_index] = verified;
    ++store->count;
    return finish_save(VIREO_OK, VIREO_CLIENT_DEADLINE_NONE, out_stage, saved_errno);
}

/**
 * @brief
 *     按完整 timer 键线性定位真实表槽。
 *
 * @param[in] store
 *     可空待检查表地址；非空时须存活，同 Reactor 只读短借。
 * @param[in] timer
 *     按值完整键；畸形拒绝、逻辑空为 NOT_FOUND。
 * @param[in] out_binding
 *     只检查外层主输出地址是否 NULL，不读取或写入。
 * @param[out] out_index
 *     本层调用者保证非空独立 size_t 地址；仅找到时发布索引。
 *
 * @return
 *     找到为 OK；NULL／畸形 INVALID_ARGUMENT；空键或未找到 NOT_FOUND；原依赖错误透传。
 *
 * @note
 *     最多 capacity 项；失败索引保持，表与主输出全部保持，不修改 errno。
 */
static vireo_result_t locate(vireo_client_deadline_store_t const *store, vireo_timer_handle_t timer,
                             vireo_client_deadline_binding_t const *out_binding,
                             size_t *out_index) {
    if (store == NULL || out_binding == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    bool empty = false;
    vireo_result_t const result = vireo_timer_handle_is_empty(timer, &empty);
    if (result != VIREO_OK) {
        return result;
    }
    if (empty) {
        return VIREO_RESULT_NOT_FOUND;
    }
    for (size_t i = 0; i < store->capacity; ++i) {
        if (same_timer(store->records[i].timer, timer)) {
            *out_index = i;
            return VIREO_OK;
        }
    }
    return VIREO_RESULT_NOT_FOUND;
}

vireo_result_t vireo_client_deadline_store_find(vireo_client_deadline_store_t const *store,
                                                vireo_timer_handle_t timer,
                                                vireo_client_deadline_binding_t *out_binding) {
    int const saved_errno = errno;
    size_t index = 0;
    vireo_result_t const result = locate(store, timer, out_binding, &index);
    if (result == VIREO_OK) {
        *out_binding = store->records[index];
    }
    return finish(result, saved_errno);
}

vireo_result_t vireo_client_deadline_store_withdraw(vireo_client_deadline_store_t *store,
                                                    vireo_timer_handle_t timer,
                                                    vireo_client_deadline_binding_t *out_binding) {
    int const saved_errno = errno;
    size_t index = 0;
    vireo_result_t const result = locate(store, timer, out_binding, &index);
    if (result == VIREO_OK) {
        *out_binding = store->records[index];
        store->records[index] = (vireo_client_deadline_binding_t){0};
        --store->count;
    }
    return finish(result, saved_errno);
}

vireo_result_t vireo_client_deadline_store_take_expired(
    vireo_client_deadline_store_t *store, vireo_timer_wheel_expired_t const *expired,
    vireo_client_deadline_binding_t *out_binding) {
    int const saved_errno = errno;
    if (expired == NULL) {
        return finish(VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    return finish(vireo_client_deadline_store_withdraw(store, expired->handle, out_binding),
                  saved_errno);
}

vireo_result_t vireo_client_deadline_store_destroy(vireo_client_deadline_store_t **store) {
    int const saved_errno = errno;
    if (store == NULL) {
        return finish(VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    if (*store != NULL && (*store)->count != 0) {
        return finish(VIREO_RESULT_BUSY, saved_errno);
    }
    free(*store);
    *store = NULL;
    return finish(VIREO_OK, saved_errno);
}
