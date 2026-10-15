/* 本层测试seam；不是下游合同，不引用server或notifier私有头。 */
#ifndef VIREO_NET_NOTIFIER_SERVER_INTERNAL_H
#define VIREO_NET_NOTIFIER_SERVER_INTERNAL_H
#include <vireo/net/notifier_server.h>

/** 表/context仅借至本调用返回；错误保持/成功转移沿公开依赖，不持久保存。 */
typedef struct vireo_notifier_server_ops {
    vireo_result_t (*inspect)(void *, vireo_notifier_t const *, vireo_notifier_info_t *);
    vireo_result_t (*bind)(void *, vireo_tcp_server_t *, int, vireo_event_loop_handle_t *,
        vireo_tcp_server_auxiliary_error_t *);
    vireo_result_t (*unbind)(void *, vireo_tcp_server_t *, vireo_event_loop_handle_t *,
        vireo_tcp_server_auxiliary_error_t *);
} vireo_notifier_server_ops_t;
/** 仅本层测试，必需完整表；其余沿register与errno合同。 */
vireo_result_t vireo_notifier_server_register_with_ops(vireo_tcp_server_t *,
    vireo_notifier_t const *, vireo_event_loop_handle_t *, vireo_notifier_server_error_t *,
    vireo_notifier_server_ops_t const *, void *);
/** 仅本层测试，必需完整表；其余沿unregister与errno合同。 */
vireo_result_t vireo_notifier_server_unregister_with_ops(vireo_tcp_server_t *,
    vireo_event_loop_handle_t *, vireo_notifier_server_error_t *,
    vireo_notifier_server_ops_t const *, void *);
#endif /* VIREO_NET_NOTIFIER_SERVER_INTERNAL_H */
