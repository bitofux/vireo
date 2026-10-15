/*
 * PROJECT : VIREO
 * FILE    : inflight_instance.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 先完整桥接后一次受检发行，不回绕、不退号、不自旋
 * IMPLEMENTATION : 局部 instance=1 仅供已验证桥接检查，绝不发布或登记；
 *                  relaxed 原子只保证累计值唯一，不承担客户或 metadata 发布。
 */
#include "inflight_instance_internal.h"

#include <vireo/base/checked.h>

#include <errno.h>

/**
 * @brief
 *     对累计值只尝试一次真实 strong CAS，不循环或伪造成功。
 *
 * @param[in] context
 *     未使用，可空。
 * @param[in,out] counter
 *     有效原子累计值，short borrow。
 * @param[in,out] expected
 *     独立局部预期，失败由 C11 原子写回观测值。
 * @param[in] desired
 *     已受检的非零下一值。
 *
 * @return
 *     true 已提交 desired；false 未提交，由调用层报告 BUSY。
 *
 * @note
 *     relaxed 只需要编号唯一，不能替代对象发布；不承诺硬实时。
 */
static bool compare_once(void *context, _Atomic(uint64_t) *counter,
                         uint64_t *expected, uint64_t desired) {
    (void)context;
    return atomic_compare_exchange_strong_explicit(counter, expected, desired,
                                                   memory_order_relaxed, memory_order_relaxed);
}

/* 仅此翻译单元可见；没有 reset 或向测试暴露生产计数器的入口。 */
static vireo_inflight_instance_issuer_t process_issuer = {
    ATOMIC_VAR_INIT(UINT64_C(0)), compare_once, NULL};

/**
 * @brief
 *     发布可空独立阶段并恢复入口 errno，不写主输出。
 *
 * @param[in] result
 *     此路径真实结果。
 * @param[in] detail
 *     成功 NONE，否则原桥接阶段或 ISSUE_INSTANCE。
 * @param[out] stage
 *     可空独立输出，只借至返回。
 * @param[in] saved_errno
 *     入口 errno 快照。
 *
 * @return
 *     原 result，不自动重试。
 */
static vireo_result_t finish(vireo_result_t result, vireo_inflight_stage_t detail,
                             vireo_inflight_stage_t *stage, int saved_errno) {
    if (stage != NULL) *stage = detail;
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_inflight_metadata_make_next_with_issuer(
    vireo_inflight_instance_issuer_t *issuer, vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, uint32_t request_sequence,
    uint32_t operation, uint64_t deadline_ns, vireo_task_metadata_t *out_metadata,
    vireo_inflight_stage_t *stage) {
    int const saved_errno = errno;
    if (out_metadata == NULL || issuer == NULL || issuer->compare_exchange == NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE, stage, saved_errno);

    vireo_task_metadata_t value;
    vireo_inflight_stage_t detail = VIREO_INFLIGHT_NONE;
    vireo_result_t result = vireo_inflight_metadata_make(server, client, request_sequence,
                                                         1, operation, deadline_ns, &value, &detail);
    if (result != VIREO_OK) return finish(result, detail, stage, saved_errno);

    uint64_t expected = atomic_load_explicit(&issuer->last_issued, memory_order_relaxed);
    uint64_t next;
    result = vireo_checked_u64_add(expected, 1, &next);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_ISSUE_INSTANCE, stage, saved_errno);
    if (!issuer->compare_exchange(issuer->context, &issuer->last_issued, &expected, next))
        return finish(VIREO_RESULT_BUSY, VIREO_INFLIGHT_ISSUE_INSTANCE, stage, saved_errno);

    /* 完整元数据已验证；仅替换有效非零实例，之后没有依赖或可失败步骤。 */
    value.request_instance_id = next;
    *out_metadata = value;
    return finish(VIREO_OK, VIREO_INFLIGHT_NONE, stage, saved_errno);
}

vireo_result_t vireo_inflight_metadata_make_next(vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, uint32_t request_sequence,
    uint32_t operation, uint64_t deadline_ns, vireo_task_metadata_t *out_metadata,
    vireo_inflight_stage_t *stage) {
    return vireo_inflight_metadata_make_next_with_issuer(&process_issuer, server, client,
        request_sequence, operation, deadline_ns, out_metadata, stage);
}
