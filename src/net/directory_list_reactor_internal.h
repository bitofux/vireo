/* PROJECT: VIREO; FILE: directory_list_reactor_internal.h; DATE: 2026-10-23.
 * 同net层七命令LIST状态与恢复，固定heap存放整页。 */
#ifndef VIREO_NET_DIRECTORY_LIST_REACTOR_INTERNAL_H
#define VIREO_NET_DIRECTORY_LIST_REACTOR_INTERNAL_H
#include "directory_root_reactor_internal.h"
#include <vireo/net/directory_list_reactor.h>
#include <vireo/service/directory_list_completion.h>
/** Every member is Reactor-owned; task remains exclusively in the original client slot. */
typedef struct vireo_list_head {
    unsigned state; /**< 0 empty / 1 needs consume / 2 consumed. */
    size_t frame_bytes; /**< Exact original frame length. */
    uint32_t sequence; /**< Original request sequence. */
    vireo_status_t status; /**< Local rejection status only. */
    bool transferred; /**< Actual task transfer, independent of rc. */
    vireo_result_t fatal; /**< First infrastructure error. */
    unsigned rejection; /**< 0 needs enqueue / 1 needs refresh / 2 refreshed. */
    vireo_inflight_submit_report_t submit; /**< Original submit/rollback facts. */
} vireo_list_head_t;
typedef struct vireo_list_receipt {
    unsigned state; /**< 0 empty / 1 taken / 2 enqueued / 3 needs destroy. */
    vireo_directory_list_completion_outcome_t outcome; /**< Independent decoded value, never a view. */
    vireo_inflight_completion_match_t match; /**< Original one-time take facts. */
} vireo_list_receipt_t;
typedef struct vireo_list_reactor_workspace {
    vireo_node_list_response_t response; /**< Independent projected response for this attempt. */
    unsigned char wire[VIREO_NODE_LIST_RESPONSE_FRAME_MAX]; /**< Codec wire, no VLC1 prefix. */
} vireo_list_reactor_workspace_t;
typedef struct vireo_list_reactor_ops {
    void *context; /**< Test context borrowed until service destruction. */
    vireo_result_t (*utc)(void *,uint64_t *);
    vireo_result_t (*monotonic)(void *,uint64_t *);
    vireo_result_t (*consume)(void *,vireo_tcp_server_t *,vireo_connection_pool_lease_t,size_t);
    vireo_result_t (*enqueue)(void *,vireo_tcp_server_t *,vireo_connection_pool_lease_t,const unsigned char *,size_t);
    vireo_result_t (*refresh)(void *,vireo_tcp_server_t *,vireo_connection_pool_lease_t);
    vireo_result_t (*submit)(void *,vireo_inflight_store_t *,const vireo_tcp_server_t *,vireo_thread_pool_t *,size_t,vireo_task_t **,vireo_inflight_submit_report_t *);
    vireo_result_t (*create_task)(void *,vireo_task_metadata_t,uint32_t,const unsigned char *,size_t,const vireo_mysql_node_actor_t *,size_t,vireo_task_t **);
} vireo_list_reactor_ops_t;
typedef struct vireo_list_reactor_state {
    vireo_completion_queue_t *queue; /**< Long borrowed dedicated queue. */
    uint32_t operation; /**< Immutable LIST operation. */
    size_t byte_budget; /**< Immutable positive worst-payload reservation per once. */
    vireo_completion_t *completion; /**< Unique owned pending completion, NULL until pop. */
    vireo_list_receipt_t receipt; /**< Own delivery progress and independent page. */
    vireo_list_reactor_workspace_t workspace; /**< Fixed heap storage, not a per-call stack object. */
    vireo_list_head_t *heads; /**< Owned array, service.capacity entries. */
    vireo_node_list_request_t *requests; /**< Owned side mirror, service.expected_capacity entries. */
    vireo_directory_list_reactor_report_t report; /**< Last once's value report. */
    vireo_list_reactor_ops_t ops; /**< Copied same-layer dependency seams. */
} vireo_list_reactor_state_t;
_Static_assert(sizeof(vireo_list_reactor_workspace_t)<=49152,"LIST workspace target");
_Static_assert(sizeof(vireo_list_reactor_state_t)<=98304,"LIST fixed state target excluding arrays");
/** Reactor-only同层入口；短借公开依赖，保持errno由外层保证。 */
void vireo_list_reactor_default_ops(vireo_list_reactor_ops_t *);
vireo_result_t vireo_list_reactor_head(vireo_auth_service_t *,client_slot_t *,vireo_connection_frame_view_t,vireo_auth_service_report_t *);
vireo_result_t vireo_list_reactor_finish_head(vireo_auth_service_t *,client_slot_t *,vireo_auth_service_report_t *);
vireo_result_t vireo_list_reactor_completions(vireo_auth_service_t *,vireo_auth_service_report_t *);
vireo_result_t vireo_list_reactor_discard(vireo_auth_service_t *);
/** 只擦相应side mirror，调用方独立维护共有镜像计数。 */
void vireo_list_reactor_clear_request(vireo_auth_service_t *,size_t);
#endif
