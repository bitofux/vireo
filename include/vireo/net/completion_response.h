/*
 * PROJECT : VIREO
 * FILE    : completion_response.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 独立完成结果的单帧编码、整帧入队及显式关注刷新
 */
#ifndef VIREO_NET_COMPLETION_RESPONSE_H
#define VIREO_NET_COMPLETION_RESPONSE_H
#include <vireo/net/inflight_completion.h>
#include <vireo/protocol/codec.h>

/** 单调用整帧字节硬上限，不含任何默认 workspace 或分配。 */
#define VIREO_COMPLETION_RESPONSE_MAX_FRAME_BYTES \
    ((size_t)VIREO_PROTOCOL_HEADER_SIZE + (size_t)VIREO_PROTOCOL_MAX_BODY_SIZE)

/** caller 显式关联原请求的 wire 描述；不认证业务/schema/handle 权限。 */
typedef struct vireo_completion_response_descriptor {
    vireo_command_t command; /**< 已注册 wire 命令，不由内部 operation 推断。 */
    vireo_protocol_flags_t extra_flags; /**< 仅 0 或 LONG_COMMAND，额外固定 RESPONSE。 */
    uint32_t session_handle; /**< caller 提供的有限 wire 数值，0 可用。 */
    uint32_t task_handle; /**< caller 提供的有限 wire 数值，0 可用。 */
} vireo_completion_response_descriptor_t;

/** 仅本接线层阶段，原 server/codec 枚举保持。 */
typedef enum vireo_completion_response_stage {
    VIREO_COMPLETION_RESPONSE_NONE = 0,
    VIREO_COMPLETION_RESPONSE_CHECK_COMPLETION = 1,
    VIREO_COMPLETION_RESPONSE_CHECK_MATCH = 2,
    VIREO_COMPLETION_RESPONSE_CHECK_CLIENT = 3,
    VIREO_COMPLETION_RESPONSE_CHECK_SERVER = 4,
    VIREO_COMPLETION_RESPONSE_BORROW_PAYLOAD = 5,
    VIREO_COMPLETION_RESPONSE_CHECK_FRAME = 6,
    VIREO_COMPLETION_RESPONSE_VALIDATE_RESPONSE = 7,
    VIREO_COMPLETION_RESPONSE_ENCODE_FRAME = 8,
    VIREO_COMPLETION_RESPONSE_ENQUEUE = 9,
    VIREO_COMPLETION_RESPONSE_REFRESH = 10
} vireo_completion_response_stage_t;

/** 每可写路径发布的按值进度；失败不等于资源整体保持。 */
typedef struct vireo_completion_response_report {
    vireo_completion_response_stage_t stage; /**< 主错位置，成功/基本拒绝 NONE。 */
    size_t frame_bytes; /**< 受检算出的整帧长度，0 表示尚未算出，不表示已入队。 */
    bool frame_encoded; /**< 完整有效 header/body/CRC 已写到 scratch 前缀。 */
    bool enqueue_called; /**< 实际调用过一次公开完整入队。 */
    bool enqueued; /**< 原 enqueue 返回 OK，整帧复制已确认。 */
    bool refresh_called; /**< 实际调用过一次公开流控关注刷新。 */
    vireo_protocol_codec_issue_t codec_issue; /**< 原响应基础校验问题，其他阶段 NONE。 */
    vireo_tcp_server_client_error_t client_error; /**< 原 enqueue 或 refresh 诊断。 */
} vireo_completion_response_report_t;

/**
 * @brief
 *     在安全点核对完成关联，编码一个有限响应并完整入队、刷新 WRITE/水位。
 *
 * @param[in,out] server
 *     必需存活资源根，服务轮返回/原 observer 或交付安全窗口使用，Reactor-only。
 * @param[in] completion
 *     必需存活结果，只读短借到返回，不移动/销毁或保存裸指针。
 * @param[in] match
 *     未篡改的公开成功匹配/交付快照；caller 保证来源与因果，不授发送权限。
 * @param[in] descriptor
 *     显式 wire 描述；caller 保证对应原请求、命令分类/body schema/handles 语义。
 * @param[in] max_frame_bytes
 *     32..MAX_FRAME_BYTES 的 size_t 整帧字节上限，无默认，限制复制及 CRC 工作。
 * @param[in,out] workspace
 *     必需独立可写 scratch，失败不保证内容保持，地址只借到返回。
 * @param[in] workspace_size
 *     实际可写容量，至少 max_frame_bytes；仅有效整帧前缀用于入队。
 * @param[out] report
 *     必需独立可写进度，每可写路径覆盖，NULL 拒绝无处发布。
 *
 * @retval VIREO_OK
 *     整帧已复制进原发送 FIFO，关注已按当前水位同步，不证明 send 或客户端收到。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL、无效 match/完成描述、快照不一致或不支持的 extra_flags。
 * @retval VIREO_RESULT_RANGE
 *     整帧上限/workspace 范围，或响应超过协议/单次/客户固定写容量。
 * @retval VIREO_RESULT_OVERFLOW
 *     受检 32+body 不可表示，或原依赖受检计算耗尽。
 * @retval VIREO_RESULT_NOT_FOUND
 *     客户空/旧代，或当前客户未附着 loop/未启用 flow，其他缺失沿原依赖。
 * @retval VIREO_RESULT_CANCELLED
 *     当前客户核验后观测到 server 已请求永久停止。
 * @retval VIREO_RESULT_BUSY
 *     当前 closing、有限在途保护，或原 enqueue 空余不足，不等待/部分复制。
 * @retval VIREO_RESULT_PROTOCOL
 *     原响应基础校验拒绝 wire command 等，codec_issue 保原问题。
 *
 * @return
 *     其余公开依赖错误透传，不回滚、自动重试/重放或清理原结果。
 *
 * @note
 *     顺序：基本/预算→完成描述→match 全形态及完整请求快照→当前客户→停止→
 *     OPEN/附着/flow→借 body→受检整帧/范围→响应基础校验→编码/CRC→enqueue→refresh。
 *     仅 RESPONSE 加可选 LONG，无 MORE/chunk；sequence 回显匹配请求，status 取
 *     suggested_status，body 原样复制，result/operation 不强转为 wire 状态或命令。
 *     codec 不验证业务 schema/命令分类/handles 权限；deadline/cancel 政策由 caller 筛选。
 *
 * @note
 *     不查已结束 inflight、不结束登记；原 deliver 之前可能已经 take，失败后原消费链
 *     保结果 owner 却不回滚登记。caller 保存原 match/描述及报告选择直接恢复或清理，
 *     不能重新播放整个消费链。必须保证同一结果不重复入队，不提供内部去重。
 *     enqueued 仅原 OK 时 true；普通容量拒绝不复制，异常依赖不承诺修复损坏状态。
 *     enqueue OK 后 refresh 错仍保待发字节，禁止再次 enqueue，应恢复刷新/发送或关闭。
 *
 * @note
 *     所有输入/输出/scratch/资源/errno 有效、对齐、独立不重叠。借用期间不得归还/关闭
 *     目标或移动/销毁 completion，正常结束短借后返回；使用原交付链时沿其回调规则。
 *     无本层申请/锁/新 owner，复制与 CRC 有界但不保证硬实时；不 send、等空间或扩容。
 *     原调用者负责禁 POSIX 取消，全部路径保持入口 errno；停止快照不提供跨线程屏障。
 */
vireo_result_t vireo_completion_response_enqueue(vireo_tcp_server_t *server,
    vireo_completion_t const *completion, vireo_inflight_completion_match_t match,
    vireo_completion_response_descriptor_t descriptor, size_t max_frame_bytes,
    uint8_t *workspace, size_t workspace_size, vireo_completion_response_report_t *report);
#endif /* VIREO_NET_COMPLETION_RESPONSE_H */
