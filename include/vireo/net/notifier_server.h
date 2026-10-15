/*
 * PROJECT : VIREO
 * FILE    : notifier_server.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : notifier fd 经公开server入口登记/注销，不借出server内部loop
 */
#ifndef VIREO_NET_NOTIFIER_SERVER_H
#define VIREO_NET_NOTIFIER_SERVER_H
#include <vireo/net/tcp_server.h>
#include <vireo/thread/notifier.h>

/** 仅本适配层阶段，不重排原server/loop阶段。 */
typedef enum vireo_notifier_server_stage {
    VIREO_NOTIFIER_SERVER_NONE = 0,
    VIREO_NOTIFIER_SERVER_INSPECT_NOTIFIER = 1,
    VIREO_NOTIFIER_SERVER_REGISTER = 2,
    VIREO_NOTIFIER_SERVER_UNREGISTER = 3
} vireo_notifier_server_stage_t;

/** 独立原因副本，不拥有或保活notifier、server或注册。 */
typedef struct vireo_notifier_server_error {
    vireo_notifier_server_stage_t stage;
    vireo_tcp_server_auxiliary_error_t server_error;
} vireo_notifier_server_error_t;

/**
 * @brief
 *     公开观察notifier fd后一次登记server单辅助LT READ，不消费提示。
 *
 * @param[in,out] server
 *     必需存活资源，须显式预留至少一项；同server最多一个辅助绑定。
 * @param[in] notifier
 *     必需存活owner的短借；注册期间fd长期借用，不close/dup/改标志/直接I/O。
 * @param[out] out_handle
 *     必需独立原完整loop handle，入口两字段全零，完整成功才发布。
 * @param[out] error
 *     可空独立诊断，每路径覆盖；成功/基本拒绝NONE，未调用原因逻辑零。
 *
 * @retval VIREO_OK
 *     fd绑定已发布，无用户回调或自动消费/drain/回写。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL或非空handle输出，输出保持，无依赖调用。
 *
 * @return
 *     原公开notifier/server错误透传，包括未预留NOT_FOUND、已绑定/在途BUSY及ADD IO。
 *
 * @note
 *     Reactor-only；producer仍可沿公开notify合同并发通知。fd借用至成功注销或server
 *     自有loop真实销毁，不转移notifier所有权；普通数值副本不保活。停止后机械登记不复位。
 *     caller在服务返回或原observer安全窗口经server take_ready取标记，再显式消费。
 * @note
 *     失败保持handle/本调用登记义务，ADD失败可消耗原序号；无申请/重试/后置回滚。
 *     地址有效、对齐、独立不重叠，不位于资源或errno中，所有路径保持入口errno。
 */
vireo_result_t vireo_notifier_server_register(vireo_tcp_server_t *server,
    vireo_notifier_t const *notifier, vireo_event_loop_handle_t *out_handle,
    vireo_notifier_server_error_t *error);

/**
 * @brief
 *     一次公开server注销，成功清handle，不关闭或消费notifier。
 *
 * @param[in,out] server
 *     存活资源，Reactor-only；已停止也可用。
 * @param[in,out] handle
 *     必需独立原辅助身份，成功清零，失败整个保持；其他副本随后失效。
 * @param[out] error
 *     可空独立诊断，每路径覆盖。
 *
 * @retval VIREO_OK
 *     注册借用已结束，原notifier owner/fd保持。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL或原形态/跨域拒绝。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空/旧/非本辅助身份，不当成功。
 *
 * @return
 *     其余原server核验/注销错误原样返回，包括RANGE/BUSY/IO。
 *
 * @note
 *     失败保登记/累计位/借用，不可提前销毁notifier；无重试/close/自动stop。
 *     原server loop真实销毁也可结束借用，全部使用者须先结束；错误回收由caller明确处理。
 *     地址有效、对齐、独立不重叠，不位于资源/errno中；所有路径保持errno。
 */
vireo_result_t vireo_notifier_server_unregister(vireo_tcp_server_t *server,
    vireo_event_loop_handle_t *handle, vireo_notifier_server_error_t *error);
#endif /* VIREO_NET_NOTIFIER_SERVER_H */
