/* 本接线层隔离公开调用，不包含外模块私有头。 */
#ifndef VIREO_NET_NOTIFIER_SERVER_DISPATCH_INTERNAL_H
#define VIREO_NET_NOTIFIER_SERVER_DISPATCH_INTERNAL_H
#include <vireo/net/notifier_server_dispatch.h>

/** 稳定只读表，只借至返回；替身遵守原输出及进度合同。 */
typedef struct vireo_notifier_server_dispatch_ops {
    vireo_result_t (*take)(void *, vireo_tcp_server_t *,
        vireo_tcp_server_auxiliary_event_t *, vireo_tcp_server_auxiliary_error_t *);
        /**< 一次公开取标记，不读 eventfd。 */
    vireo_result_t (*dispatch)(void *, vireo_notifier_t *, vireo_inflight_store_t *,
        vireo_tcp_server_t const *, vireo_completion_queue_t *, size_t,
        vireo_inflight_completion_deliver_fn, void *, vireo_completion_t **,
        vireo_notifier_completion_report_t *);
        /**< 一次原消费链，保原报告及残留 owner。 */
} vireo_notifier_server_dispatch_ops_t;

/** 仅本层测试；必需完整 ops，可空短借 ops_context，其余沿公共合同及 errno 保持。 */
vireo_result_t vireo_notifier_server_dispatch_with_ops(vireo_tcp_server_t *,
    vireo_event_loop_handle_t, vireo_notifier_t *, vireo_inflight_store_t *,
    vireo_completion_queue_t *, size_t, vireo_inflight_completion_deliver_fn, void *,
    vireo_completion_t **, vireo_notifier_server_dispatch_report_t *,
    vireo_notifier_server_dispatch_ops_t const *, void *);
#endif /* VIREO_NET_NOTIFIER_SERVER_DISPATCH_INTERNAL_H */
