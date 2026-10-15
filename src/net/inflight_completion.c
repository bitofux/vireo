/*
 * PROJECT : VIREO
 * FILE    : inflight_completion.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 仅经公开合同读取完成描述、核验客户与在途记录
 */
#include <vireo/net/inflight_completion.h>

#include <errno.h>

/**
 * @brief
 *     发布独立阶段并恢复入口 errno，不发布主快照或改变资源。
 *
 * @param[in] result
 *     此路径真实结果，依赖错误不重新分类。
 * @param[in] detail
 *     此路径真实阶段，成功为 NONE。
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

vireo_result_t vireo_inflight_store_check_completion(vireo_inflight_store_t const *store,
    vireo_tcp_server_t const *server, vireo_completion_t const *completion,
    vireo_inflight_completion_match_t *out_match, vireo_inflight_stage_t *stage) {
    int const saved_errno = errno;
    if (store == NULL || server == NULL || completion == NULL || out_match == NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE, stage, saved_errno);

    vireo_completion_info_t info;
    vireo_result_t result = vireo_completion_inspect(completion, &info);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_CHECK_COMPLETION, stage, saved_errno);

    vireo_completion_metadata_t validated;
    result = vireo_completion_metadata_make(info.metadata.request, info.metadata.result,
        info.metadata.suggested_status, &validated);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_CHECK_COMPLETION, stage, saved_errno);

    vireo_inflight_completion_match_t value;
    vireo_inflight_stage_t detail = VIREO_INFLIGHT_NONE;
    result = vireo_inflight_check_client(server, validated.request, &value.close_state, &detail);
    if (result != VIREO_OK) return finish(result, detail, stage, saved_errno);

    result = vireo_inflight_store_get(store, validated.request, &value.metadata, &detail);
    if (result != VIREO_OK) return finish(result, detail, stage, saved_errno);

    if (validated.request.operation != value.metadata.operation ||
        validated.request.deadline_ns != value.metadata.deadline_ns)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_MATCH_RECORD, stage, saved_errno);

    *out_match = value;
    return finish(VIREO_OK, VIREO_INFLIGHT_NONE, stage, saved_errno);
}
