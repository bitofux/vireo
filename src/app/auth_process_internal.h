/* PROJECT: VIREO; FILE: auth_process_internal.h; AUTHOR: bitofux;
 * DATE: 2026-10-22; BRIEF: 停机join资格竞争的应用层有界恢复。 */
#ifndef VIREO_APP_AUTH_PROCESS_INTERNAL_H
#define VIREO_APP_AUTH_PROCESS_INTERNAL_H
#include <vireo/thread/thread_pool.h>
/**
 * @brief 已确认所有提交队列关闭后，仅恢复join前CHECK_QUEUE的短暂BUSY
 * @param[in,out] pool 必需存活池，管理方独占，所有callback仍可自然结束。
 * @param[in] attempts 正的最多调用次数；生产使用8192。
 * @param[in] join 必需单次公开stop_and_join接点，遵守原报告及所有权合同。
 * @param[out] out 必需独立报告，成功或失败发布最后一次真实调用前缀；基本拒绝保持。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL或零次数，未调用join。
 * @return 最后一次join原码；仅BUSY且stage=CHECK_QUEUE才yield后重试，不重试已执行业务或join错误。
 * @note 应用关闭线程专用、禁POSIX取消；可能等待SQL/线程，次数有限不限制时长。
 * 保持errno；不拥有或销毁pool，不重投、不清故障，不将BUSY业务首错误作资格竞争。
 */
vireo_result_t vireo_auth_process_join_with(vireo_thread_pool_t *pool,size_t attempts,
    vireo_result_t (*join)(vireo_thread_pool_t *,vireo_thread_pool_report_t *),
    vireo_thread_pool_report_t *out);
#endif
