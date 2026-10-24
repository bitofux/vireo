/* PROJECT : VIREO; FILE : directory_move_reactor_internal.h;
 * AUTHOR : bitofux; DATE : 2026-10-25; BRIEF : 同net层固定状态，不作为跨层合同。 */
#ifndef VIREO_NET_DIRECTORY_MOVE_REACTOR_INTERNAL_H
#define VIREO_NET_DIRECTORY_MOVE_REACTOR_INTERNAL_H
#include "directory_mkdir_reactor_internal.h"
#include <vireo/net/directory_move_reactor.h>
#include <vireo/service/directory_move_completion.h>
/** @brief 每客户一个MOVE首帧；task仍唯一owned于原slot.task。 */
typedef struct vireo_move_head {
    unsigned state; /**< 0空/1待consume/2已consume。 */
    size_t frame_bytes; /**< 原81..335精确帧边界。 */
    uint32_t sequence; /**< 原非零序号。 */
    vireo_status_t status; /**< 未交接的本地拒绝状态。 */
    bool transferred; /**< 真实交接，非OK也保持事实。 */
    vireo_result_t fatal; /**< 锁存首个基础设施错误。 */
    unsigned rejection; /**< 0待enqueue/1待refresh/2完成。 */
    vireo_inflight_submit_report_t submit; /**< 唯一submit及撤销事实。 */
} vireo_move_head_t;
/** @brief MVC1可核关联，逻辑28字节；本机u64对齐下sizeof为32，不序列化struct。 */
typedef struct vireo_move_request_key {
    uint64_t node_id; /**< 原非零source，成功响应须相同。 */
    uint32_t session_handle; /**< 原非零连接handle。 */
    unsigned char idempotency_key[16]; /**< 原16字节完整键；forget/复用前擦除含padding。 */
} vireo_move_request_key_t;
/** @brief 一次take后的独立值，无task/原payload借用。 */
typedef struct vireo_move_receipt {
    unsigned state; /**< 0空/1待enqueue/2已enqueue待refresh/3待destroy。 */
    vireo_directory_move_completion_outcome_t outcome; /**< 专用MVC1解码独立值。 */
    vireo_inflight_completion_match_t match; /**< 一次take的原关联。 */
} vireo_move_receipt_t;
/** @brief 小型固定重编码区，绝不含目标名字或执行事件。 */
typedef struct vireo_move_reactor_workspace {
    vireo_node_move_response_t response; /**< 每次首次enqueue重建或TIMEOUT。 */
    unsigned char wire[VIREO_NODE_MOVE_RESPONSE_FRAME_MAX]; /**< 最多64字节实际wire。 */
} vireo_move_reactor_workspace_t;
/** @brief 同net层注入；默认仅公开API，context借至service完全销毁。 */
typedef struct vireo_move_reactor_ops {
    void *context; /**< 可NULL；无资源所有权。 */
    vireo_result_t (*utc)(void *, uint64_t *); /**< UTC毫秒。 */
    vireo_result_t (*monotonic)(void *, uint64_t *); /**< MONOTONIC纳秒。 */
    vireo_result_t (*consume)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t, size_t); /**< 原帧消费。 */
    vireo_result_t (*enqueue)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t, const unsigned char *, size_t); /**< 整帧原子入FIFO。 */
    vireo_result_t (*refresh)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t); /**< TLS flow刷新。 */
    vireo_result_t (*submit)(void *, vireo_inflight_store_t *, const vireo_tcp_server_t *, vireo_thread_pool_t *, size_t, vireo_task_t **, vireo_inflight_submit_report_t *); /**< 真实交接报告。 */
    vireo_result_t (*create_task)(void *, vireo_task_metadata_t, uint32_t, const unsigned char *, size_t, const vireo_mysql_node_actor_t *, size_t, vireo_task_t **); /**< 04公开create，无cancel。 */
    vireo_result_t (*destroy_completion)(void *, vireo_completion_t **); /**< 公开destroy及真实owner进度。 */
} vireo_move_reactor_ops_t;
/** @brief 只在九模式申请，数组及自身全部计入原max_memory_bytes。 */
typedef struct vireo_move_reactor_state {
    vireo_completion_queue_t *queue; /**< 长借专属MOVE queue。 */
    uint32_t operation; /**< 不变可信标签。 */
    vireo_completion_t *completion; /**< 唯一已pop owner。 */
    vireo_move_receipt_t receipt; /**< 有限恢复进度。 */
    vireo_move_reactor_workspace_t workspace; /**< 固定重编码区。 */
    vireo_move_head_t *heads; /**< owned，server capacity项。 */
    vireo_move_request_key_t *requests; /**< owned，C+6项。 */
    vireo_directory_move_reactor_report_t report; /**< 去敏观察值。 */
    vireo_move_reactor_ops_t ops; /**< 按值表及长期借用context。 */
} vireo_move_reactor_state_t;
_Static_assert(sizeof(vireo_move_request_key_t) == 32, "target ABI context size, not wire size");
_Static_assert(sizeof(vireo_move_reactor_workspace_t) <= 256, "bounded response workspace");
_Static_assert(sizeof(vireo_move_reactor_state_t) <= 4096, "state excludes owned arrays");
void vireo_move_reactor_default_ops(vireo_move_reactor_ops_t *out);
vireo_result_t vireo_move_reactor_head(vireo_auth_service_t *, client_slot_t *, vireo_connection_frame_view_t, vireo_auth_service_report_t *);
vireo_result_t vireo_move_reactor_finish_head(vireo_auth_service_t *, client_slot_t *, vireo_auth_service_report_t *);
vireo_result_t vireo_move_reactor_completions(vireo_auth_service_t *, vireo_auth_service_report_t *);
vireo_result_t vireo_move_reactor_discard(vireo_auth_service_t *);
void vireo_move_reactor_clear_request(vireo_auth_service_t *, size_t);
#endif
