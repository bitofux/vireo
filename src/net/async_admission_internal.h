/* 仅本接线层公开依赖边界，不导入其他模块private头。 */
#ifndef VIREO_NET_ASYNC_ADMISSION_INTERNAL_H
#define VIREO_NET_ASYNC_ADMISSION_INTERNAL_H
#include <vireo/net/async_admission.h>

/** 完整稳定表/context只短借至本次返回，不保存/发布或改变旧布局。 */
typedef struct vireo_async_admission_ops {
    vireo_result_t (*inspect)(void *, vireo_tcp_server_t const *, vireo_tcp_server_info_t *);
        /**< 原server按值观察，替身只能改本次快照模型。 */
    vireo_result_t (*admit)(void *, vireo_tcp_server_t *, vireo_connection_options_t const *,
        vireo_tcp_server_admit_budget_t const *, vireo_connection_pool_lease_t *, size_t,
        vireo_tcp_server_admit_info_t *, vireo_tcp_server_client_error_t *);
        /**< 原有界接入，保真实租约前缀/原清理与统计。 */
    vireo_result_t (*flow)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_connection_flow_options_t const *, vireo_tcp_server_client_error_t *);
        /**< 原一次流控配置，不伪造配置提交或MOD成功。 */
    vireo_result_t (*schedule)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_tcp_server_client_error_t *);
        /**< 原一次排FIFO，错误不补排/消客户。 */
} vireo_async_admission_ops_t;

/**
 * @brief
 *     公共同实现的四公开边界seam，表/context短借；缺项INVALID，无全局替换状态。
 *
 * @param[in] ops
 *     必需完整稳定表，替身遵守原容量、真实owner与前缀合同。
 * @param[in,out] context
 *     可空独立本次短借，不包含外模块private布局。
 *
 * @return
 *     其他参数、报告/errno沿公开入口，模型与真实故障须分别说明。
 */
vireo_result_t vireo_async_admission_with_ops(vireo_tcp_server_t *, vireo_connection_options_t const *,
    vireo_connection_flow_options_t const *, vireo_tcp_server_admit_budget_t const *,
    vireo_connection_pool_lease_t *, size_t, vireo_async_admission_turn_t *, size_t,
    vireo_async_admission_report_t *, vireo_async_admission_ops_t const *, void *);
#endif /* VIREO_NET_ASYNC_ADMISSION_INTERNAL_H */
