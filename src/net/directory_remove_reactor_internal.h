/* 047-05 private fixed state for the NODE_REMOVE Reactor. */
#ifndef VIREO_NET_DIRECTORY_REMOVE_REACTOR_INTERNAL_H
#define VIREO_NET_DIRECTORY_REMOVE_REACTOR_INTERNAL_H
#include "directory_move_reactor_internal.h"
#include <vireo/net/directory_remove_reactor.h>
#include <vireo/service/directory_remove_completion.h>

typedef struct vireo_remove_receipt {
    unsigned state;
    vireo_directory_remove_completion_outcome_t outcome;
    vireo_inflight_completion_match_t match;
} vireo_remove_receipt_t;
typedef struct vireo_remove_reactor_workspace {
    vireo_node_remove_response_t response;
    unsigned char wire[VIREO_NODE_REMOVE_RESPONSE_FRAME_MAX];
} vireo_remove_reactor_workspace_t;
typedef struct vireo_remove_reactor_state {
    vireo_completion_queue_t *queue;
    uint32_t operation;
    vireo_completion_t *completion;
    vireo_remove_receipt_t receipt;
    vireo_remove_reactor_workspace_t workspace;
    vireo_move_head_t *heads;
    vireo_move_request_key_t *requests;
    vireo_directory_remove_reactor_report_t report;
    vireo_move_reactor_ops_t ops;
} vireo_remove_reactor_state_t;
_Static_assert(sizeof(vireo_remove_reactor_workspace_t)<=256,"bounded REMOVE response workspace");
_Static_assert(sizeof(vireo_remove_reactor_state_t)<=4096,"fixed state excludes arrays");

void vireo_remove_reactor_default_ops(vireo_move_reactor_ops_t *out);
vireo_result_t vireo_remove_reactor_head(vireo_auth_service_t *,client_slot_t *,vireo_connection_frame_view_t,vireo_auth_service_report_t *);
vireo_result_t vireo_remove_reactor_finish_head(vireo_auth_service_t *,client_slot_t *,vireo_auth_service_report_t *);
vireo_result_t vireo_remove_reactor_completions(vireo_auth_service_t *,vireo_auth_service_report_t *);
vireo_result_t vireo_remove_reactor_discard(vireo_auth_service_t *);
void vireo_remove_reactor_clear_request(vireo_auth_service_t *,size_t);
#endif
