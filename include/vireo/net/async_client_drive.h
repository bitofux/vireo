/*
 * PROJECT : VIREO
 * FILE    : async_client_drive.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 安全窗口内的单客户、单首帧异步驱动与真实失败前缀
 */
#ifndef VIREO_NET_ASYNC_CLIENT_DRIVE_H
#define VIREO_NET_ASYNC_CLIENT_DRIVE_H
#include <vireo/net/async_request_head.h>

/** 纯数值按值配置；不发号、采样或自动映射业务标签。 */
typedef struct vireo_async_client_drive_options {
    size_t max_frame_bytes; /**< 整帧32..MAX，另受当前read/flow容量限制。 */
    size_t task_allocation_budget; /**< 正≤64MiB，原task控制块＋整帧复制申请量。 */
    size_t max_client_requests; /**< 正客户登记上限；实际store资格沿031，可接收后拒绝。 */
    uint32_t operation; /**< 非零内部标签，不自动映射wire command。 */
    uint64_t deadline_ns; /**< 同域MONOTONIC绝对纳秒，0/MAX有限，可已到期。 */
} vireo_async_client_drive_options_t;

/** 独立正字节/系统调用预算；本入口固定最多一次首帧提交。 */
typedef struct vireo_async_client_drive_budget {
    vireo_connection_receive_budget_t receive; /**< 新接收的字节/recv调用次数。 */
    vireo_connection_send_budget_t send; /**< 原待发FIFO的字节/send调用次数。 */
} vireo_async_client_drive_budget_t;

/** 本驱动独立阶段，不重排旧server/head/提交阶段。 */
typedef enum vireo_async_client_drive_stage {
    VIREO_ASYNC_CLIENT_DRIVE_NONE = 0,
    VIREO_ASYNC_CLIENT_DRIVE_CHECK_PENDING = 1,
    VIREO_ASYNC_CLIENT_DRIVE_CHECK_SERVER = 2,
    VIREO_ASYNC_CLIENT_DRIVE_CHECK_CLIENT = 3,
    VIREO_ASYNC_CLIENT_DRIVE_PRE_REFRESH = 4,
    VIREO_ASYNC_CLIENT_DRIVE_RECEIVE = 5,
    VIREO_ASYNC_CLIENT_DRIVE_PEEK_FRAME = 6,
    VIREO_ASYNC_CLIENT_DRIVE_SUBMIT = 7,
    VIREO_ASYNC_CLIENT_DRIVE_SEND = 8,
    VIREO_ASYNC_CLIENT_DRIVE_FINAL_REFRESH = 9,
    VIREO_ASYNC_CLIENT_DRIVE_FINAL_INSPECT = 10
} vireo_async_client_drive_stage_t;

/** 每可写路径发布真实进度；没有资源owner或body指针，逻辑零不代表已执行。 */
typedef struct vireo_async_client_drive_report {
    vireo_async_client_drive_stage_t stage; /**< 主错误阶段；成功/基本拒绝NONE。 */
    bool pre_refresh_called; /**< 实际尝试入口flow刷新。 */
    bool receive_called; /**< 已实际调用原有界接收，压力/EOF时false。 */
    vireo_connection_receive_info_t receive; /**< 原接收统计，含错误前已收字节。 */
    bool frame_peek_called; /**< 已实际查看REQUEST首帧，不消费。 */
    vireo_connection_frame_info_t frame_info; /**< 原查看统计/停止原因。 */
    bool request_header_available; /**< 成功识别完整首帧并复制原header，不代表已提交。 */
    vireo_protocol_header_t request_header; /**< 原header按值关联；available才有来源意义。 */
    bool head_called; /**< 已实际调用一次031提交/消费入口。 */
    vireo_async_request_head_report_t head_report; /**< 原移交/残留/退款及pending消费前缀。 */
    bool send_called; /**< 实际尝试发送旧FIFO；首业务错时false。 */
    vireo_connection_send_info_t send; /**< 原发送统计，不等本次task响应。 */
    bool final_refresh_called; /**< pre刷新成功后实际一次末刷新。 */
    vireo_result_t final_refresh_result; /**< called才表示原末刷新结果。 */
    vireo_tcp_server_client_error_t final_refresh_error; /**< 独立末刷新诊断，不覆盖主错。 */
    bool final_inspect_called; /**< 前步骤全OK后实际最终客户观察。 */
    vireo_tcp_server_client_error_t client_error; /**< 主客户操作诊断；提交原原因在head_report。 */
    bool needs_reschedule; /**< 全部成功且本首帧消费后有读缓存，caller可显式排尾。 */
    bool pending_retained; /**< 已校验pending或本次031消费义务最终仍非空。 */
} vireo_async_client_drive_report_t;

/**
 * @brief
 *     安全点驱动一个OPEN异步客户，最多提交一个首帧，保留原头与真实失败责任。
 *
 * @param[in,out] server
 *     必需存活资源根，只在033poll返回或原observer安全窗口调用，不在sync handler内。
 * @param[in] client
 *     caller选定异步处理的完整租约；当前OPEN且已绑定/启用flow。
 * @param[in,out] store
 *     原在途登记表，实际容量/准入检查沿031，可能已接收后拒绝。
 * @param[in,out] pool
 *     原固定池，提交与其他管理caller串行，worker可并发领取独立副本。
 * @param[in] options
 *     必需独立五数值，入口复制；帧/申请上限及正limit/非零operation。
 * @param[in] budget
 *     必需独立收/发双正字节及syscall预算，入口复制，不默认扩大。
 * @param[in] cancel
 *     可空来源强引用，非空保持至返回，不消费来源、不自动请求取消。
 * @param[in,out] pending
 *     每完整客户唯一caller值，入口逻辑空；非空先显式原resume恢复，不自动清除。
 * @param[out] remaining_task
 *     必需独占入口NULL，已创建未转移的失败残留交caller，不自动销毁。
 * @param[out] report
 *     必需独立可写完整报告，每可写路径发布，失败仍查原head移交/消费标志。
 *
 * @retval VIREO_OK
 *     有界步骤完成，包括无完整首帧；不保证worker完成、响应或peer收到。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL/零参数/非空remaining/畸形pending；报告发布，资源保持。
 * @retval VIREO_RESULT_RANGE
 *     帧或task预算超公开上限/当前read-flow不兼容；其余范围沿原依赖。
 * @retval VIREO_RESULT_BUSY
 *     合法非空pending、六有限阶段在途或客户closing；不自动恢复或重试。
 * @retval VIREO_RESULT_CANCELLED
 *     入口server已观测停止；不是同步屏障，晚到stop仍可能在031准入拒绝。
 * @retval VIREO_RESULT_NOT_FOUND
 *     未绑定/未flow，或原旧客户/池等依赖拒绝，不能当作消费成功。
 * @return
 *     其余公开依赖错误透传；前置无字节变化，进入执行后保真实部分进度。
 *
 * @note
 *     顺序：基本/范围/pending→公开server六在途/stop→当前客户/容量→pre刷新→压力观察。
 *     非EOF且无读写压力才receive；缓存REQUEST仍可查看/提交，随后send旧字节。
 *     保存完整原header值并结束view使用，再一次031，原真实transfer才consume规则保持。
 *     不自动映射operation/command，不把CRC/header当鉴权，不混用同客户旧同步输入处理。
 *
 * @note
 *     首业务错跳过后续业务；pre成功后仍一次final刷新，主错优先，次错独立。
 *     pre失败不final重试；原transfer/consume/send字节不回滚或重放，pending保持原义务。
 *     错误后旧输出caller可单独有界send；不能无条件重排BUSY导致忙循环。
 *     只有全OK、本项transfer/consume成功且最终read缓存非空才给续排提示，可能仅半帧。
 *
 * @note
 *     不wait/accept/消费结果/回写响应/自动schedule/关闭归还或join；没有自有长期资源。
 *     只try提交不等队列容量；原task复制会申请，不保证整段硬实时或完全非阻塞。
 *     全部同资源Reactor-only、禁POSIX取消，输出/输入/资源独立有效对齐且不重叠。
 *     caller入口结束旧read借用并统一pending源，不存view/body指针，不给worker网络资源。
 *     全部受控路径保持入口errno；只有原request_stop例外可跨线程，观察非同步屏障。
 */
vireo_result_t vireo_async_client_drive_once(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_inflight_store_t *store, vireo_thread_pool_t *pool,
    vireo_async_client_drive_options_t const *options, vireo_async_client_drive_budget_t const *budget,
    vireo_task_cancel_t *cancel, vireo_async_request_pending_t *pending, vireo_task_t **remaining_task,
    vireo_async_client_drive_report_t *report);
#endif /* VIREO_NET_ASYNC_CLIENT_DRIVE_H */
