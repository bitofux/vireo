/* 045-05 同net层私有MKDIR状态；不跨层公开布局。 */
#ifndef VIREO_NET_DIRECTORY_MKDIR_REACTOR_INTERNAL_H
#define VIREO_NET_DIRECTORY_MKDIR_REACTOR_INTERNAL_H
#include "directory_list_reactor_internal.h"
#include <vireo/net/directory_mkdir_reactor.h>
#include <vireo/service/directory_mkdir_completion.h>
/** @brief 唯一客户首帧进度；task仍只owned于原slot.task。 */
typedef struct vireo_mkdir_head {
    unsigned state; /**< 0 empty/1 needs consume/2 consumed。 */
    size_t frame_bytes; /**< 原69..323字节精确边界。 */
    uint32_t sequence; /**< 原非零序号。 */
    vireo_command_t command; /**< MKDIR或八模式限额拒绝的原auth命令。 */
    vireo_status_t status; /**< 本地32字节拒绝状态。 */
    bool transferred; /**< 原真实交接，即使rc非OK。 */
    vireo_result_t fatal; /**< 基础设施首错，不因consume恢复覆盖。 */
    unsigned rejection; /**< 0 needs enqueue/1 needs refresh/2 refreshed。 */
    vireo_inflight_submit_report_t submit; /**< 原一次submit/rollback事实。 */
} vireo_mkdir_head_t;
/** @brief side镜像仅保VMC1可重复核的上下文，原metadata/actor在共有expected。 */
typedef struct vireo_mkdir_request_key {
    uint32_t session_handle; /**< 原非零handle。 */
    unsigned char idempotency_key[16]; /**< 原非零key；退镜像/复用前擦除。 */
} vireo_mkdir_request_key_t;
/** @brief 独立完成交付进度，不借原payload或task。 */
typedef struct vireo_mkdir_receipt {
    unsigned state; /**< 0 empty/1 taken/2 enqueued needs refresh/3 needs destroy。 */
    vireo_directory_mkdir_completion_outcome_t outcome; /**< 专用decode值，无name/event。 */
    vireo_inflight_completion_match_t match; /**< 一次take的原事实。 */
} vireo_mkdir_receipt_t;
/** @brief 本层固定heap，小wire按01 codec重新编码。 */
typedef struct vireo_mkdir_reactor_workspace {
    vireo_node_mkdir_response_t response; /**< 每首次enqueue尝试重建，可能TIMEOUT。 */
    unsigned char wire[VIREO_NODE_MKDIR_RESPONSE_FRAME_MAX]; /**< 最多64；无VMC1。 */
} vireo_mkdir_reactor_workspace_t;
/** @brief 同net层单次公开依赖接点，context长借到service销毁。 */
typedef struct vireo_mkdir_reactor_ops {
    void *context;
    vireo_result_t (*utc)(void *,uint64_t *);
    vireo_result_t (*monotonic)(void *,uint64_t *);
    vireo_result_t (*consume)(void *,vireo_tcp_server_t *,vireo_connection_pool_lease_t,size_t);
    vireo_result_t (*enqueue)(void *,vireo_tcp_server_t *,vireo_connection_pool_lease_t,const unsigned char *,size_t);
    vireo_result_t (*refresh)(void *,vireo_tcp_server_t *,vireo_connection_pool_lease_t);
    vireo_result_t (*submit)(void *,vireo_inflight_store_t *,const vireo_tcp_server_t *,vireo_thread_pool_t *,size_t,vireo_task_t **,vireo_inflight_submit_report_t *);
    vireo_result_t (*create_task)(void *,vireo_task_metadata_t,uint32_t,const unsigned char *,size_t,const vireo_mysql_node_actor_t *,size_t,vireo_task_t **);
    vireo_result_t (*destroy_completion)(void *,vireo_completion_t **); /**< 同层测试清理短进度，默认公开destroy。 */
} vireo_mkdir_reactor_ops_t;
/** @brief Reactor独占；只在八模式申请，所有数组纳入总预算。 */
typedef struct vireo_mkdir_reactor_state {
    vireo_completion_queue_t *queue; /**< 长借专属queue。 */
    uint32_t operation; /**< 不变op。 */
    vireo_completion_t *completion; /**< 唯一pop后owner，转移前NULL。 */
    vireo_mkdir_receipt_t receipt;
    vireo_mkdir_reactor_workspace_t workspace;
    vireo_mkdir_head_t *heads; /**< owned，server capacity项。 */
    vireo_mkdir_request_key_t *requests; /**< owned，共有expected_capacity=C+5项。 */
    vireo_directory_mkdir_reactor_report_t report;
    vireo_mkdir_reactor_ops_t ops; /**< 复制操作表与长借context。 */
} vireo_mkdir_reactor_state_t;
_Static_assert(sizeof(vireo_mkdir_request_key_t)==20,"compact context on target ABI");
_Static_assert(sizeof(vireo_mkdir_reactor_workspace_t)<=256,"bounded small workspace");
_Static_assert(sizeof(vireo_mkdir_reactor_state_t)<=4096,"fixed state excludes arrays");
void vireo_mkdir_reactor_default_ops(vireo_mkdir_reactor_ops_t *);
vireo_result_t vireo_mkdir_reactor_head(vireo_auth_service_t *,client_slot_t *,vireo_connection_frame_view_t,vireo_auth_service_report_t *);
vireo_result_t vireo_mkdir_reactor_finish_head(vireo_auth_service_t *,client_slot_t *,vireo_auth_service_report_t *);
vireo_result_t vireo_mkdir_reactor_completions(vireo_auth_service_t *,vireo_auth_service_report_t *);
vireo_result_t vireo_mkdir_reactor_discard(vireo_auth_service_t *);
vireo_result_t vireo_mkdir_reactor_reject_auth(vireo_auth_service_t *,client_slot_t *,vireo_connection_frame_view_t,vireo_auth_service_report_t *);
void vireo_mkdir_reactor_clear_request(vireo_auth_service_t *,size_t);
#endif
