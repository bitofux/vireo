/*
 * PROJECT : VIREO
 * FILE    : async_request_head.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 首帧移交后的消费义务、caller 待消费记录与防重
 */
#ifndef VIREO_NET_ASYNC_REQUEST_HEAD_H
#define VIREO_NET_ASYNC_REQUEST_HEAD_H
#include <vireo/net/async_request.h>

/** caller 每客户唯一保存；全逻辑零为空，非空是合法 metadata＋32..MAX 帧长。 */
typedef struct vireo_async_request_pending {
    vireo_task_metadata_t metadata; /**< 已真实移交请求的完整身份，不保活客户/task。 */
    size_t frame_bytes; /**< 原读区尚需消费的首帧字节数，不是 task/queue 深度。 */
} vireo_async_request_pending_t;

/** 本入口独立阶段，旧 server/提交阶段保持。 */
typedef enum vireo_async_request_head_stage {
    VIREO_ASYNC_REQUEST_HEAD_NONE = 0,
    VIREO_ASYNC_REQUEST_HEAD_CHECK_PENDING = 1,
    VIREO_ASYNC_REQUEST_HEAD_PEEK_FRAME = 2,
    VIREO_ASYNC_REQUEST_HEAD_PEEK_BYTES = 3,
    VIREO_ASYNC_REQUEST_HEAD_SUBMIT = 4,
    VIREO_ASYNC_REQUEST_HEAD_CONSUME = 5
} vireo_async_request_head_stage_t;

/** 按值真实前缀，没有借用 body/fd/owner 指针；called 区分未调用逻辑零。 */
typedef struct vireo_async_request_head_report {
    vireo_async_request_head_stage_t stage; /**< 主错位置，成功/基本拒绝 NONE。 */
    bool frame_peek_called; /**< 实际调用过一次公开 REQUEST 首帧识别。 */
    vireo_connection_frame_info_t frame_info; /**< 原帧统计，含半帧/空 EOF 原停止原因。 */
    bool frame_found; /**< 本次识别发现完整首帧，恢复入口不重新识别。 */
    size_t frame_bytes; /**< 本次首帧或历史 pending 的待消费字节。 */
    bool read_peek_called; /**< 本次实际借用过连续原读区前缀。 */
    vireo_tcp_server_client_error_t frame_error; /**< 原 frames/read peek 诊断。 */
    bool submit_called; /**< 实际调用过一次原完整帧复制/提交。 */
    vireo_result_t submit_result; /**< 原提交结果，仅 submit_called 有效。 */
    vireo_async_request_report_t submit_report; /**< 原发行/复制/交接/撤销前缀。 */
    bool pending_committed; /**< 本次真实移交后曾写 pending，消费后清空也保 true。 */
    bool pending_retained; /**< 已校验的 pending 在本调用结束仍非空。 */
    bool consume_called; /**< 实际尝试一次原读区消费。 */
    vireo_result_t consume_result; /**< 原消费结果，仅 consume_called 有效。 */
    vireo_tcp_server_client_error_t consume_error; /**< 原消费独立诊断，不覆盖提交主错。 */
    vireo_async_request_pending_t pending_snapshot; /**< 有效非空/提交后/消费前的历史值，不保活。 */
} vireo_async_request_head_report_t;

/**
 * @brief
 *     安全点识别一个首帧并提交，真实移交后保存消费义务，再一次消费原请求。
 *
 * @param[in,out] server
 *     必需资源根，服务轮返回/原 observer 安全窗口，不在同步 handler 内调用。
 * @param[in] client
 *     原当前完整客户租约；caller 为此客户唯一使用同一 pending。
 * @param[in,out] store
 *     原在途表，登记/取消引用/撤销沿031-01。
 * @param[in,out] pool
 *     原池，提交与管理由 caller 串行，worker 可并发领取独立 task。
 * @param[in] max_frame_bytes
 *     32..MAX；另受原客户读容量/flow 帧上限限制，识别预算固定1项/本帧上限。
 * @param[in] task_allocation_budget
 *     原显式正 task 申请预算，最多64MiB，无新默认或本层申请。
 * @param[in] max_client_requests
 *     原显式正客户请求限额，准入沿原提交，可能复制后拒绝。
 * @param[in] operation
 *     原显式非零内部标签，不自动映射 wire command。
 * @param[in] deadline_ns
 *     原有限 MONOTONIC 绝对纳秒，0/MAX可已到期，不采样/筛选。
 * @param[in] cancel
 *     原可空 cancel，非空来源强引用保活到返回，不消费来源。
 * @param[in,out] pending
 *     必需 caller 独立唯一值，初逻辑零；非空拒绝新提交并保值。
 * @param[out] remaining_task
 *     必需独占入口NULL，未转移的原新 task 残留交caller。
 * @param[out] report
 *     必需独立可写报告，每可写路径发布真实主次错/进度。
 *
 * @retval VIREO_OK
 *     无完整首帧（含空EOF）无动作，或提交/消费均成功；不保证执行或回写。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL、零task预算/限额/operation、非空remaining或畸形pending。
 * @retval VIREO_RESULT_RANGE
 *     帧上限非法，或原客户读/flow容量、task预算、限额等依赖拒绝。
 * @retval VIREO_RESULT_BUSY
 *     已有有效非空pending，不peek/发行/复制；其他竞争/准入沿原依赖。
 *
 * @return
 *     其他依赖原错透传。提交非OK保主错，消费错另报；提交OK时消费错为主错。
 *
 * @note
 *     基本/范围/pending形态→若非空BUSY→一次REQUEST frames_peek→有首帧时一次
 *     read_peek→一次031-01。仅submit_report.task_transferred真时写metadata＋frame_bytes，
 *     即使提交报错也一次consume；消费OK清整个pending，失败保消费义务，不退款/重提。
 *     原帧基础校验/CRC不包括业务schema/鉴权，完整wire副本仍沿031-01重新验证。
 *
 * @note
 *     caller入口前结束所有旧读借用使用；本层复制返回后结束内部body/raw借用才consume。
 *     每客户一份pending，统一本入口、不能复制gate/绕过031-01或擅自清有效记录。
 *     非空恢复前不得另行receive/consume/release或改该读区；记录不保活，客户已明确归还
 *     时caller保存审计值后可弃置，NOT_FOUND不自动视为消费成功。不承诺跨绕过/篡改恰好一次。
 *
 * @note
 *     同资源Reactor-only，全调用禁POSIX取消；地址有效对齐独立且不重叠资源/输出/errno。
 *     所有路径保持errno；不recv/flow刷新/自动响应/关闭/运行服务/重复尝试/destroy残留。
 *     原task申请/引用/CRC不保证整段无阻塞或hard realtime，原queue不等容量。
 */
vireo_result_t vireo_async_request_submit_read_head(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_inflight_store_t *store, vireo_thread_pool_t *pool,
    size_t max_frame_bytes, size_t task_allocation_budget, size_t max_client_requests,
    uint32_t operation, uint64_t deadline_ns, vireo_task_cancel_t *cancel,
    vireo_async_request_pending_t *pending, vireo_task_t **remaining_task,
    vireo_async_request_head_report_t *report);

/**
 * @brief
 *     仅按合法非空pending恢复一次原首帧消费，不识别/构造/发号/提交。
 *
 * @param[in,out] server
 *     原资源根，机械消费允许停止/closing，客户当前性沿原consume。
 * @param[in,out] pending
 *     原唯一非空值，caller保证客户原首帧未另行消费/接收/释放或改写。
 * @param[out] report
 *     必需独立可写真实报告，每可写路径覆盖；保存消费前值，未调用字段逻辑零。
 *
 * @retval VIREO_OK
 *     原帧已消费且pending清空，不代表worker或结果登记仍活跃/已完成。
 * @retval VIREO_RESULT_NOT_FOUND
 *     逻辑空pending，或原客户旧代/已归还；后者保记录，不当成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL/畸形pending，其他跨域等错误沿原依赖。
 *
 * @return
 *     其他consume原错透传、失败保pending；不内部重试/清理/再次提交。
 *
 * @note
 *     只从metadata.route取原完整租约，不查询inflight；完成登记已take也可恢复消费。
 *     pending与源稳定/唯一及借用规则沿提交入口；空记录重复恢复不是重复consume。
 *     原消费不flow刷新；所有路径保持errno，禁POSIX取消，同资源Reactor-only。
 */
vireo_result_t vireo_async_request_resume_consume(vireo_tcp_server_t *server,
    vireo_async_request_pending_t *pending, vireo_async_request_head_report_t *report);
#endif /* VIREO_NET_ASYNC_REQUEST_HEAD_H */
