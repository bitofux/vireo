/* 本核心私有公开边界seam，下游不得依赖。 */
#ifndef VIREO_ASYNC_ADMISSION_PRESSURE_INTERNAL_H
#define VIREO_ASYNC_ADMISSION_PRESSURE_INTERNAL_H
#include <vireo/net/async_admission_pressure.h>

/** 只替换本层两项公开调用，不读取server隐藏布局。 */
typedef struct vireo_async_admission_pressure_ops {
    vireo_result_t (*inspect)(void *, vireo_tcp_server_t const *, vireo_tcp_server_info_t *); /**< 只读容量快照。 */
    vireo_result_t (*set_read)(void *, vireo_tcp_server_t *, bool, vireo_tcp_server_listener_error_t *); /**< 一次公开READ更新。 */
} vireo_async_admission_pressure_ops_t;

/**
 * @brief
 *     本层隔离调用表入口，仅测试故障或公开适配使用。
 *
 * @param[in] ops
 *     两函数均非空，稳定至返回；不保存、不保活。
 * @param[in,out] context
 *     可空独立短借上下文，依调用者的公开合同处理。
 *
 * @return
 *     原refresh合同；不完整表INVALID_ARGUMENT。
 *
 * @note
 *     server/options/report沿公共入口，失败不扩大资源回滚承诺，保持errno。
 */
vireo_result_t vireo_async_admission_pressure_with_ops(vireo_tcp_server_t *server,
    vireo_connection_options_t const *connection_options, vireo_async_admission_pressure_report_t *report,
    vireo_async_admission_pressure_ops_t const *ops, void *context);
#endif
