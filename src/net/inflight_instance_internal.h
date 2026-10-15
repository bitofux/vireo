/*
 * PROJECT : VIREO
 * FILE    : inflight_instance_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 本核心隔离发行器与单次 CAS 故障入口，不是下游合同
 */
#ifndef VIREO_NET_INFLIGHT_INSTANCE_INTERNAL_H
#define VIREO_NET_INFLIGHT_INSTANCE_INTERNAL_H

#include <vireo/net/inflight.h>

#include <stdatomic.h>

/** 仅本核心实现/测试使用；初始化后操作与 context 固定，累计值只原子访问。 */
typedef struct vireo_inflight_instance_issuer {
    _Atomic(uint64_t) last_issued; /**< 累计成功值；初 0，MAX 后不再发行。 */
    bool (*compare_exchange)(void *context, _Atomic(uint64_t) *counter,
                            uint64_t *expected, uint64_t desired); /**< strong CAS，relaxed 成败序。 */
    void *context; /**< 可空操作上下文，短借至全部发行访问结束。 */
} vireo_inflight_instance_issuer_t;

/**
 * @brief
 *     用本核心隔离发行器执行完整桥接，允许测试真实耗尽/一次竞争。
 *
 * @param[in,out] issuer
 *     必需有效发行器，操作非空；last 只经原子访问，初始化后不重置。
 * @param[in] server
 *     与公开入口相同的短借 Reactor 资源根。
 * @param[in] client
 *     完整按值客户租约，与公开入口相同。
 * @param[in] request_sequence
 *     非零协议标签。
 * @param[in] operation
 *     非零内部标签。
 * @param[in] deadline_ns
 *     有限 MONOTONIC 绝对纳秒。
 * @param[out] out_metadata
 *     必需独立输出，失败全部字节保持。
 * @param[out] stage
 *     可空独立阶段，每可写路径覆盖。
 *
 * @return
 *     沿公开入口原结果；额外 issuer/操作 NULL 为 INVALID_ARGUMENT/NONE。
 *
 * @note
 *     操作须遵循 strong CAS：不伪成功，失败不提交 desired；context 不保存到输出。
 *     测试只建自己的局部发行器，不访问或重置生产静态发行器。
 *     全部路径保持 errno；无申请、内部循环或发行后可失败步骤。
 */
vireo_result_t vireo_inflight_metadata_make_next_with_issuer(
    vireo_inflight_instance_issuer_t *issuer, vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, uint32_t request_sequence,
    uint32_t operation, uint64_t deadline_ns, vireo_task_metadata_t *out_metadata,
    vireo_inflight_stage_t *stage);

#endif
