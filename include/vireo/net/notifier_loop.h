/*
 * PROJECT : VIREO
 * FILE    : notifier_loop.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : notifier fd 的固定 READ 注册借用与显式注销
 */
#ifndef VIREO_NET_NOTIFIER_LOOP_H
#define VIREO_NET_NOTIFIER_LOOP_H
#include <vireo/net/event_loop.h>
#include <vireo/thread/notifier.h>

/** 本适配层诊断阶段，与原 event loop 阶段独立，不是 wire 值。 */
typedef enum vireo_notifier_loop_stage {
    VIREO_NOTIFIER_LOOP_NONE = 0, /**< 成功或本层基本拒绝。 */
    VIREO_NOTIFIER_LOOP_INSPECT_NOTIFIER = 1, /**< 公开读取 notifier fd 失败。 */
    VIREO_NOTIFIER_LOOP_REGISTER = 2, /**< 公开 loop ADD 返回错误。 */
    VIREO_NOTIFIER_LOOP_UNREGISTER = 3 /**< 公开 loop DEL 返回错误。 */
} vireo_notifier_loop_stage_t;

/** 独立按值诊断，不拥有或保活 loop、notifier、注册或 context。 */
typedef struct vireo_notifier_loop_error {
    vireo_notifier_loop_stage_t stage; /**< 本调用错误位置；每可写路径覆盖。 */
    vireo_event_loop_error_t loop_error; /**< 原 ADD/DEL 诊断；未调用时逻辑零。 */
} vireo_notifier_loop_error_t;

/**
 * @brief
 *     公开观察 notifier fd 后一次注册固定 LT READ，不执行或包装 caller 回调。
 *
 * @param[in,out] loop
 *     必需存活公开 loop，Reactor-only；登记借用，不转移其 owner。
 * @param[in] notifier
 *     必需存活对象，原 owner 保持；fd 非负且 0 合法，不 close/dup/改标志。
 * @param[in] callback
 *     必需原 loop void 回调，注册期间代码存活，须有界非阻塞并正常返回。
 * @param[in,out] context
 *     可空，按值传入原 loop 绑定；非空须在注册及已执行回调期间存活。
 * @param[out] out_handle
 *     必需独立、对齐、可写数值输出，入口 loop_id/token 均为零；不保存地址。
 * @param[out] out_error
 *     可空独立、可写诊断，每路径覆盖；成功/基本拒绝 NONE、嵌套逻辑零。
 *
 * @retval VIREO_OK
 *     完整绑定已登记并发布原完整 loop handle，没有消费提示或调用回调。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、callback NULL 或 out_handle 非空，不调用依赖，保持 handle。
 *
 * @return
 *     其余公开依赖错误原样返回，重复 fd/表满 BUSY、原发号耗尽 OVERFLOW、ADD IO 等。
 *
 * @note
 *     fd/code/context 借用至成功注销或 loop 销毁；已执行回调的代码/context 到返回。
 *     借用存活时不得销毁 notifier 或提前释放 code/context；数值副本不延长寿命。
 *     notifier producer 可按原公开合同并发 notify，对象发布/寿命由 caller 同步。
 *
 * @note
 *     仅固定 READ，不新增关注位选项；callback/context 固定，改变需先 DEL 再 ADD。
 *     允许已停止 loop 机械登记，但其运行仍不分发，不复位或承诺恢复。
 *     回调是 void，内部错误由 caller 记录，不自动使原 run/run_once 返回错误。
 *
 * @note
 *     失败保持整个 handle 和本调用登记义务；ADD 失败可消耗原 loop 发号序号。
 *     本层无 heap/资源所有权/默认容量或预算、自动回滚或重试，所有路径保持 errno。
 *     不读提示、领队列、安排再次通知、进入 server 私有 loop、网络回写或停止/join。
 *     所有地址须有效、对齐、存活且彼此独立，不与资源/context/errno 存储重叠。
 */
vireo_result_t vireo_notifier_loop_register(vireo_event_loop_t *loop,
    vireo_notifier_t const *notifier, vireo_event_loop_callback_t callback, void *context,
    vireo_event_loop_handle_t *out_handle, vireo_notifier_loop_error_t *out_error);

/**
 * @brief
 *     一次公开 DEL 结束原注册借用，成功清空该 handle 副本，不关闭 notifier。
 *
 * @param[in,out] loop
 *     必需存活公开 loop，Reactor-only，借至返回，不停止或销毁。
 * @param[in,out] handle
 *     必需独立、对齐、可写的原注册身份；caller 保证来自本适配层的对应注册。
 *     成功清零，其他副本随后失效；不自行构造 token，不保存地址。
 * @param[out] out_error
 *     可空独立可写诊断，每路径覆盖；成功/基本 NULL 拒绝为 NONE/嵌套零。
 *
 * @retval VIREO_OK
 *     原注册已注销，handle 清零，notifier fd 和 owner 保持。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL；原畸形/跨 loop 依赖错误也透传。
 * @retval VIREO_RESULT_NOT_FOUND
 *     原空/旧身份，不自动当成功，保持原 handle 与调用责任。
 *
 * @return
 *     其他公开 DEL 错误原样返回，包括槽范围 RANGE 和系统 IO/原诊断。
 *
 * @note
 *     本入口不认证任意其他注册的业务来源，不观察 notifier 或消费计数。
 *     DEL 失败保完整 handle、注册及借用；不能提前 free context/销毁 notifier。
 *     可在原 loop 回调自注销，但已执行代码/context 仍须安全存活至回调返回。
 *     停止全部使用后原 loop destroy 也可结束注册，不由本入口自动执行。
 *
 * @note
 *     无分配、close、内部重试/回滚；所有路径保持入口 errno，诊断可空不改变策略。
 *     输入输出存活、有效、对齐、独立，不与资源/context/errno 重叠；同 loop Reactor-only。
 */
vireo_result_t vireo_notifier_loop_unregister(vireo_event_loop_t *loop,
    vireo_event_loop_handle_t *handle, vireo_notifier_loop_error_t *out_error);
#endif /* VIREO_NET_NOTIFIER_LOOP_H */
