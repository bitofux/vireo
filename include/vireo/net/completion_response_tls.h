/*
 * PROJECT : VIREO
 * FILE    : completion_response_tls.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-18
 * BRIEF   : 完成结果的TLS单帧入队与真实关注刷新
 */
#ifndef VIREO_NET_COMPLETION_RESPONSE_TLS_H
#define VIREO_NET_COMPLETION_RESPONSE_TLS_H
#include <vireo/net/completion_response.h>
#include <vireo/net/tcp_server_tls.h>

/** TLS回写的独立值报告；不持有completion、TLS或server。 */
typedef struct vireo_completion_response_tls_report {
    vireo_completion_response_report_t response; /**< 原编码/整帧提交进度；client_error只描述enqueue。 */
    vireo_tcp_server_tls_error_t lookup_error; /**< TLS短借的原根/客户查找诊断，未调用为零。 */
    vireo_tcp_server_tls_flow_info_t flow; /**< response.refresh_called时的真实TLS关注/续调度报告。 */
    vireo_tcp_server_tls_application_error_t error; /**< 客户TLS检查原因，或refresh主因/MOD/queue独立诊断。 */
} vireo_completion_response_tls_report_t;

/**
 * @brief 核对当前TLS客户后编码一个完成响应，整帧入队并刷新TLS实际关注
 *
 * @param[in,out] server
 *     必需存活TLS根，只在Reactor安全点串行调用，无同server其他阶段在途。
 * @param[in] completion
 *     必需存活只读短借结果；不转移/销毁，不保存指针。
 * @param[in] match
 *     原成功匹配/交付快照；完整请求身份须与completion一致，caller保证来源。
 * @param[in] descriptor
 *     原请求对应wire描述；仅0/LONG_COMMAND额外flags，业务/handles权限由caller保证。
 * @param[in] max_frame_bytes
 *     32..VIREO_COMPLETION_RESPONSE_MAX_FRAME_BYTES的整帧字节上限，无默认。
 * @param[in,out] workspace
 *     必需独立可写scratch，只短借；失败允许改变已编码前缀，不与任何资源重叠。
 * @param[in] workspace_size
 *     实际可写容量，至少max_frame_bytes；只有完整帧前缀入队。
 * @param[out] report
 *     必需独立输出；每条可写路径typed覆盖，flow/error未调用部分为零。
 *
 * @retval VIREO_OK
 *     完整明文响应已复制进唯一TLS写FIFO，真实关注及本地续调度已刷新；不证明已发。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL、不支持flags、无效描述或completion/match完整身份不一致。
 * @retval VIREO_RESULT_RANGE
 *     帧/workspace范围错误，或响应超过协议/单次/固定TLS写容量；
 *     ENQUEUE阶段也可表示当前写FIFO空余不足，保持原TLS分类，不部分复制。
 * @retval VIREO_RESULT_OVERFLOW
 *     受检长度不可表示，或原依赖受检计数耗尽。
 * @retval VIREO_RESULT_NOT_FOUND
 *     客户旧代/已释放/未绑定，或原依赖缺失。
 * @retval VIREO_RESULT_BUSY
 *     RAW/未建立/PREPARED/FAILED/已请求TLS关闭/同server在途，或原依赖有限保护。
 * @retval VIREO_RESULT_CANCELLED
 *     核验客户后观察到server永久停止。
 * @retval VIREO_RESULT_PROTOCOL
 *     响应基础wire校验失败，或TLS公开检查依赖的协议失败。
 * @retval VIREO_RESULT_IO
 *     原公开TLS刷新MOD等IO失败；原errno保存在嵌套诊断中。
 * @retval VIREO_RESULT_INTERNAL
 *     原检查/关注/续调度状态异常；其他公开依赖分类原样返回。
 *
 * @note 基本预算→完成/match→当前客户→停止→TLS模式/附着/握手/IO OPEN/close NONE→
 *     借body→受检整帧→基础响应校验/编码/CRC→一次enqueue→一次TLS flow_refresh。
 *     TLS read_eof不禁止反向响应；关闭请求后拒绝新响应。不使用RAW close/flow占位字段。
 *     RESPONSE加可选LONG，sequence回显match，status取suggested_status，body原样复制；
 *     不查/结束inflight，不处理deadline/cancel业务政策，不认证业务schema。
 * @note enqueued=true后即使刷新失败也保留完整待发字节，caller只能显式补TLS flow_refresh
 *     或关闭，禁止为补关注再次enqueue/重放消费链。容量拒绝不部分复制，不内部去重。
 *     completion始终归caller；所有地址有效、对齐、独立，借用期间不释放目标/结果。
 * @note 无本层申请、锁、native TLS读写、等待、自动重试或释放；复制/CRC受整帧上限约束。
 *     保持入口errno；不修改进程信号；公开TLS观察会清本线程OpenSSL错误队列。caller禁POSIX取消。
 *     旧RAW入口及其报告/签名不变；TLS验证/刷新诊断在error中，enqueue诊断在response中。
 */
vireo_result_t vireo_completion_response_tls_enqueue(vireo_tcp_server_t *server,
    vireo_completion_t const *completion, vireo_inflight_completion_match_t match,
    vireo_completion_response_descriptor_t descriptor, size_t max_frame_bytes,
    uint8_t *workspace, size_t workspace_size, vireo_completion_response_tls_report_t *report);
#endif /* VIREO_NET_COMPLETION_RESPONSE_TLS_H */
