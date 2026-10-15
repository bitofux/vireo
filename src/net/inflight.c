/*
 * PROJECT : VIREO
 * FILE    : inflight.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 只依公开 server/task 合同的无资源身份桥接
 */
#include <vireo/net/inflight.h>

#include <errno.h>

/**
 * @brief
 *     发布独立阶段并恢复入口 errno，不写主输出或资源。
 *
 * @param[in] result
 *     此路径真实结果，依赖错误不重新分类。
 * @param[in] detail
 *     此路径阶段；成功为 NONE。
 * @param[out] stage
 *     可空独立输出，只借至返回。
 * @param[in] saved_errno
 *     入口保存的 errno。
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

vireo_result_t vireo_inflight_metadata_make(vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, uint32_t request_sequence,
    uint64_t request_instance_id, uint32_t operation, uint64_t deadline_ns,
    vireo_task_metadata_t *out_metadata, vireo_inflight_stage_t *stage) {
    int const saved_errno = errno;
    bool const empty = client.pool_id == 0 && client.slot_index == 0 && client.generation == 0;
    if (server == NULL || out_metadata == NULL || request_sequence == 0 ||
        request_instance_id == 0 || operation == 0 ||
        (!empty && (client.pool_id == 0 || client.generation == 0))) {
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE, stage, saved_errno);
    }

    vireo_tcp_server_client_info_t client_info;
    vireo_result_t result = vireo_tcp_server_client_inspect(server, client, &client_info);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_CHECK_CLIENT, stage, saved_errno);

    vireo_task_route_t route;
    result = vireo_task_route_make(client.pool_id, client.slot_index, client.generation,
                                    request_sequence, &route);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_MAKE_ROUTE, stage, saved_errno);

    vireo_task_metadata_t value;
    result = vireo_task_metadata_make(route, request_instance_id, operation, deadline_ns, &value);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_MAKE_METADATA, stage, saved_errno);

    *out_metadata = value;
    return finish(VIREO_OK, VIREO_INFLIGHT_NONE, stage, saved_errno);
}

vireo_result_t vireo_inflight_check_client(vireo_tcp_server_t const *server,
    vireo_task_metadata_t metadata, vireo_connection_close_state_t *out_close_state,
    vireo_inflight_stage_t *stage) {
    int const saved_errno = errno;
    if (server == NULL || out_close_state == NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE, stage, saved_errno);

    /* 公开构造器在局部检查完整形态；不复制其他核心的私有校验函数。 */
    vireo_task_metadata_t validated;
    vireo_result_t result = vireo_task_metadata_make(metadata.route, metadata.request_instance_id,
                                                    metadata.operation, metadata.deadline_ns,
                                                    &validated);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_CHECK_METADATA, stage, saved_errno);

    vireo_connection_pool_lease_t const client = {
        validated.route.client_owner_id, validated.route.client_slot_index,
        validated.route.client_generation};
    vireo_tcp_server_client_info_t info;
    result = vireo_tcp_server_client_inspect(server, client, &info);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_CHECK_CLIENT, stage, saved_errno);

    vireo_connection_close_state_t const state = info.connection_info.close_state;
    if (state != VIREO_CONNECTION_CLOSE_OPEN && state != VIREO_CONNECTION_CLOSE_DRAINING &&
        state != VIREO_CONNECTION_CLOSE_READY)
        return finish(VIREO_RESULT_INTERNAL, VIREO_INFLIGHT_CHECK_CLIENT, stage, saved_errno);

    *out_close_state = state;
    return finish(VIREO_OK, VIREO_INFLIGHT_NONE, stage, saved_errno);
}
