/*
 * PROJECT : VIREO
 * FILE    : async_request.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 精确单帧验证、独立任务复制与真实限额提交
 */
#ifndef VIREO_NET_ASYNC_REQUEST_H
#define VIREO_NET_ASYNC_REQUEST_H
#include <vireo/net/inflight_submit.h>
#include <vireo/protocol/codec.h>

/** 完整请求帧字节硬上限，没有默认输入或申请预算。 */
#define VIREO_ASYNC_REQUEST_MAX_FRAME_BYTES \
    ((size_t)VIREO_PROTOCOL_HEADER_SIZE + (size_t)VIREO_PROTOCOL_MAX_BODY_SIZE)

/** 本入口独立阶段，不重排 codec/inflight/pool 的阶段。 */
typedef enum vireo_async_request_stage {
    VIREO_ASYNC_REQUEST_NONE = 0,
    VIREO_ASYNC_REQUEST_CHECK_FRAME = 1,
    VIREO_ASYNC_REQUEST_MAKE_METADATA = 2,
    VIREO_ASYNC_REQUEST_CREATE_TASK = 3,
    VIREO_ASYNC_REQUEST_SUBMIT = 4
} vireo_async_request_stage_t;

/** 按值真实前缀，不拥有或保活资源；原读区全程未消费。 */
typedef struct vireo_async_request_report {
    vireo_async_request_stage_t stage; /**< 主错位置，成功/基本拒绝 NONE。 */
    size_t frame_bytes; /**< 受检算出的头加声明 body 字节，非提交量。 */
    bool input_validated; /**< 精确单 REQUEST 帧与 CRC 已通过，不代表业务或认证。 */
    vireo_task_metadata_t metadata; /**< metadata_created 才是本调用发行快照。 */
    bool metadata_created; /**< 发号成功，后段失败也不退号。 */
    bool task_created; /**< 曾成功创建独立 task，不表示最终仍由 caller 拥有。 */
    bool submit_called; /**< 实际调用过原限额提交入口。 */
    bool task_transferred; /**< 原 pool 报告确认转移，报错时也不能退款/重新构造。 */
    bool task_retained; /**< 本调用新 task 最终在 remaining_task，非所有源 owner 的观测。 */
    vireo_protocol_codec_issue_t codec_issue; /**< 原 codec 问题，精确长度不符 BODY_LENGTH_MISMATCH。 */
    vireo_inflight_stage_t inflight_stage; /**< 原元数据桥接诊断，提交诊断在 submit_report。 */
    vireo_inflight_submit_report_t submit_report; /**< 原登记/交接/一次撤销真实前缀。 */
} vireo_async_request_report_t;

/**
 * @brief
 *     安全点验证一个完整请求帧，复制成独立 task，再一次限额登记和尝试提交。
 *
 * @param[in] server
 *     必需当前客户资源根，仅短借至返回，不在原同步 handler 内调用。
 * @param[in] client
 *     完整客户租约；caller 保证 data 来自该客户当前读区的未篡改单帧。
 * @param[in,out] store
 *     必需在途表，登记/可选取消引用及撤销沿原公开合同。
 * @param[in,out] pool
 *     必需池；本提交与同池管理 caller 串行，worker 可并发领取。
 * @param[in] data
 *     必需连续可读单帧 wire，包含 32 字节头，只借到返回，不保存地址。
 * @param[in] size
 *     实际可读字节数，须精确等于一帧；不接受半帧或多帧尾部。
 * @param[in] max_frame_bytes
 *     显式 32..16777248 整帧上限，无默认，限制 CRC/复制字节工作。
 * @param[in] task_allocation_budget
 *     显式正预算，最多 64 MiB，沿 task 受检控制块＋完整 wire 帧申请量。
 * @param[in] max_client_requests
 *     显式正限额，表容量范围/OPEN/停止/冲突等准入沿原提交，可能复制后拒绝。
 * @param[in] operation
 *     显式非零内部标签，不自动映射 wire command；业务适用性 caller 保证。
 * @param[in] deadline_ns
 *     同域 MONOTONIC 绝对纳秒，0/MAX 有限且可已到期，不采样/筛选。
 * @param[in] cancel
 *     可空；非空须 caller 强引用保活到返回，task 增持一份，不消费来源。
 * @param[out] remaining_task
 *     必需独占入口 NULL 的 owner 地址；创建后未转移的失败交回新 task。
 * @param[out] report
 *     必需独立可写真实前缀，每可写路径覆盖。
 *
 * @retval VIREO_OK
 *     原登记和提交已完成，task 已转移；不保证执行/回投/响应，源请求未消费。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL、零 operation/申请预算/限额或非空 remaining_task，其他沿依赖。
 * @retval VIREO_RESULT_RANGE
 *     单帧上限非法或 size 不在 32..上限；申请预算/限额/表容量沿依赖。
 * @retval VIREO_RESULT_PROTOCOL
 *     不是精确完整单帧、REQUEST 基础语义非法或 CRC 不符，codec_issue 保存问题。
 * @retval VIREO_RESULT_OVERFLOW
 *     受检帧计算/发行/引用或原依赖耗尽，不回绕/退号。
 * @retval VIREO_RESULT_NO_MEMORY
 *     原 task 申请失败，没有发布半对象。
 *
 * @return
 *     其他公开依赖原错透传，旧提交退款错另保其原报告，不覆盖主错。
 *
 * @note
 *     基本/范围→decode→REQUEST 基础校验→受检精确帧长→CRC→make_next→copy→try_submit。
 *     payload 是整帧 wire 字节副本，不是宿主 header ABI；worker 没有网络借用指针/fd。
 *     caller 负责来源关联、命令专属 schema/鉴权/handles；CRC 不认证客户身份。
 *     cancel 为空走普通 copy，非空走 with_cancel；已请求取消允许构造，不自动取消。
 *
 * @note
 *     发号后不退；创建失败无 task，未转移的后段错误保新 task 在 remaining_task。
 *     已转移即使报错也保原登记，不使用旧裸 task 指针，不退款或重新构造。
 *     原撤销失败可同时保登记与 caller task，须先恢复本义务，不盲目再次登记。
 *     未自动 destroy、重试、回滚、编码错误响应、request_cancel 或关闭资源。
 *
 * @note
 *     全程不 receive/consume/刷新关注；caller 在返回前不得 receive/consume/release
 *     源客户。已提交请求仍在读区，caller 必须防重复处理并另按转移进度显式消费。
 *     同资源 Reactor-only，全调用禁 POSIX 取消；有效对齐独立存储不重叠资源/输出/errno。
 *     所有路径保持入口 errno；申请和引用不保证无阻塞/公平/硬实时，queue 提交不等容量。
 */
vireo_result_t vireo_async_request_copy_try_submit(vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, vireo_inflight_store_t *store, vireo_thread_pool_t *pool,
    uint8_t const *data, size_t size, size_t max_frame_bytes, size_t task_allocation_budget,
    size_t max_client_requests, uint32_t operation, uint64_t deadline_ns,
    vireo_task_cancel_t *cancel, vireo_task_t **remaining_task, vireo_async_request_report_t *report);
#endif /* VIREO_NET_ASYNC_REQUEST_H */
