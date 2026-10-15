/*
 * PROJECT : VIREO
 * FILE    : notifier_loop.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 无本层资源，顺序观察并固定 READ ADD，显式一次 DEL
 */
#include "notifier_loop_internal.h"
#include <errno.h>

/** 只转发一次公开资源快照，不保存 context/notifier/info。 */
static vireo_result_t inspect_public(void *context, vireo_notifier_t const *notifier,
    vireo_notifier_info_t *info) {
    (void)context;
    return vireo_notifier_inspect(notifier, info);
}

/** 只转发一次公开 ADD，资源及输出责任原样保留。 */
static vireo_result_t add_public(void *context, vireo_event_loop_t *loop,
    vireo_event_loop_registration_t const *registration, vireo_event_loop_handle_t *handle,
    vireo_event_loop_error_t *error) {
    (void)context;
    return vireo_event_loop_add(loop, registration, handle, error);
}

/** 只转发一次公开 DEL，不关闭 fd 或释放 context。 */
static vireo_result_t del_public(void *context, vireo_event_loop_t *loop,
    vireo_event_loop_handle_t *handle, vireo_event_loop_error_t *error) {
    (void)context;
    return vireo_event_loop_del(loop, handle, error);
}

/** 只读默认函数表，不含本层可变状态或任何长期资源 owner。 */
static vireo_notifier_loop_ops_t const default_ops = {inspect_public, add_public, del_public};

/**
 * @brief
 *     每可写路径发布完整诊断，恢复 errno，原样返回原错误。
 *
 * @param[in] result
 *     本路径原返回类别。
 * @param[in] stage
 *     本层位置，基本拒绝 NONE；成功统一为 NONE。
 * @param[in] value
 *     原 loop 独立诊断，未调用时逻辑零。
 * @param[out] error
 *     可空独立可写诊断。
 * @param[in] saved_errno
 *     入口原 int 值。
 *
 * @return
 *     原 result，无资源清理或再次调用依赖。
 */
static vireo_result_t finish(vireo_result_t result, vireo_notifier_loop_stage_t stage,
    vireo_event_loop_error_t value, vireo_notifier_loop_error_t *error, int saved_errno) {
    if (error != NULL) *error = (vireo_notifier_loop_error_t){
        result == VIREO_OK ? VIREO_NOTIFIER_LOOP_NONE : stage, value};
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_notifier_loop_register_with_ops(vireo_event_loop_t *loop,
    vireo_notifier_t const *notifier, vireo_event_loop_callback_t callback, void *context,
    vireo_event_loop_handle_t *handle, vireo_notifier_loop_error_t *error,
    vireo_notifier_loop_ops_t const *ops, void *ops_context) {
    int const saved_errno = errno;
    vireo_event_loop_error_t value = {0};
    if (loop == NULL || notifier == NULL || callback == NULL || handle == NULL ||
        ops == NULL || ops->inspect == NULL || ops->add == NULL ||
        handle->loop_id != 0 || handle->token != 0)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_NOTIFIER_LOOP_NONE, value, error, saved_errno);
    vireo_notifier_info_t info;
    vireo_result_t result = ops->inspect(ops_context, notifier, &info);
    if (result != VIREO_OK)
        return finish(result, VIREO_NOTIFIER_LOOP_INSPECT_NOTIFIER, value, error, saved_errno);
    vireo_event_loop_registration_t const registration = {
        info.fd, VIREO_EPOLL_INTEREST_READ, callback, context};
    result = ops->add(ops_context, loop, &registration, handle, &value);
    return finish(result, VIREO_NOTIFIER_LOOP_REGISTER, value, error, saved_errno);
}

vireo_result_t vireo_notifier_loop_unregister_with_ops(vireo_event_loop_t *loop,
    vireo_event_loop_handle_t *handle, vireo_notifier_loop_error_t *error,
    vireo_notifier_loop_ops_t const *ops, void *ops_context) {
    int const saved_errno = errno;
    vireo_event_loop_error_t value = {0};
    if (loop == NULL || handle == NULL || ops == NULL || ops->del == NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_NOTIFIER_LOOP_NONE, value, error, saved_errno);
    vireo_result_t const result = ops->del(ops_context, loop, handle, &value);
    return finish(result, VIREO_NOTIFIER_LOOP_UNREGISTER, value, error, saved_errno);
}

vireo_result_t vireo_notifier_loop_register(vireo_event_loop_t *loop,
    vireo_notifier_t const *notifier, vireo_event_loop_callback_t callback, void *context,
    vireo_event_loop_handle_t *handle, vireo_notifier_loop_error_t *error) {
    return vireo_notifier_loop_register_with_ops(loop, notifier, callback, context,
        handle, error, &default_ops, NULL);
}

vireo_result_t vireo_notifier_loop_unregister(vireo_event_loop_t *loop,
    vireo_event_loop_handle_t *handle, vireo_notifier_loop_error_t *error) {
    return vireo_notifier_loop_unregister_with_ops(loop, handle, error, &default_ops, NULL);
}
