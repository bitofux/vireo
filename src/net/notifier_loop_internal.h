/*
 * PROJECT : VIREO
 * FILE    : notifier_loop_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 本适配层的隔离公开依赖调用 seam
 */
#ifndef VIREO_NET_NOTIFIER_LOOP_INTERNAL_H
#define VIREO_NET_NOTIFIER_LOOP_INTERNAL_H
#include <vireo/net/notifier_loop.h>

/** 稳定只读短借表，遵守原公开输出/注册合同，不保存参数或访问外 private。 */
typedef struct vireo_notifier_loop_ops {
    vireo_result_t (*inspect)(void *context, vireo_notifier_t const *notifier,
        vireo_notifier_info_t *info); /**< 一次公开资源快照，不读取计数。 */
    vireo_result_t (*add)(void *context, vireo_event_loop_t *loop,
        vireo_event_loop_registration_t const *registration, vireo_event_loop_handle_t *handle,
        vireo_event_loop_error_t *error); /**< 一次原 ADD，失败保持 handle/登记义务。 */
    vireo_result_t (*del)(void *context, vireo_event_loop_t *loop,
        vireo_event_loop_handle_t *handle, vireo_event_loop_error_t *error);
        /**< 一次原 DEL，成功清 handle，失败保持借用。 */
} vireo_notifier_loop_ops_t;

/**
 * @brief
 *     register 的同一实现，只替换本层公开依赖调用用于隔离故障模型。
 *
 * @param[in,out] loop
 *     沿公共 register 的有效短借 loop。
 * @param[in] notifier
 *     沿公共 register 的有效对象，注册借用规则不变。
 * @param[in] callback
 *     沿公共 register 的必需有界正常返回代码。
 * @param[in,out] context
 *     可空 callback 上下文，沿原长期绑定借用。
 * @param[out] handle
 *     必需入口全零的独立输出。
 * @param[out] error
 *     可空独立诊断，每路径覆盖。
 * @param[in] ops
 *     必需稳定只读表；本入口要求 inspect/add 非空，不保存。
 * @param[in,out] ops_context
 *     可空隔离上下文，仅借至返回，不与资源/输出重叠。
 *
 * @return
 *     沿公共入口；缺失所需 ops 为 INVALID_ARGUMENT，诊断 NONE/零，无调用。
 *
 * @note
 *     所有路径保持 errno；故障模型不是实际内核失败证据，不用外模块私有布局。
 */
vireo_result_t vireo_notifier_loop_register_with_ops(vireo_event_loop_t *loop,
    vireo_notifier_t const *notifier, vireo_event_loop_callback_t callback, void *context,
    vireo_event_loop_handle_t *handle, vireo_notifier_loop_error_t *error,
    vireo_notifier_loop_ops_t const *ops, void *ops_context);

/**
 * @brief
 *     unregister 的同一实现，只替换一次本层 DEL 调用。
 *
 * @param[in,out] loop
 *     沿公共 unregister 的有效短借 loop。
 * @param[in,out] handle
 *     沿公共 unregister 的独立原注册身份。
 * @param[out] error
 *     可空独立诊断，每路径覆盖。
 * @param[in] ops
 *     必需稳定只读表，本入口仅要求 del 非空，不保存。
 * @param[in,out] ops_context
 *     可空隔离上下文，只借至返回，不与资源/输出重叠。
 *
 * @return
 *     沿公共入口；缺失所需 ops 为 INVALID_ARGUMENT、NONE/零且无调用。
 *
 * @note
 *     所有路径保持 errno，DEL 失败借用仍活，模型故障不冒 OS 实际失败。
 */
vireo_result_t vireo_notifier_loop_unregister_with_ops(vireo_event_loop_t *loop,
    vireo_event_loop_handle_t *handle, vireo_notifier_loop_error_t *error,
    vireo_notifier_loop_ops_t const *ops, void *ops_context);
#endif /* VIREO_NET_NOTIFIER_LOOP_INTERNAL_H */
