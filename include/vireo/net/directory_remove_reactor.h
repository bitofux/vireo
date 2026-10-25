/* 047-05 production NODE_REMOVE Reactor/TLS integration. */
#ifndef VIREO_NET_DIRECTORY_REMOVE_REACTOR_H
#define VIREO_NET_DIRECTORY_REMOVE_REACTOR_H
#include <vireo/net/directory_move_reactor.h>
#include <vireo/service/directory_remove_completion.h>

typedef struct vireo_directory_remove_reactor_report {
    size_t submitted, rejected, completions, identity_discarded, late_discarded, deadline_downgraded;
    bool response_blocked, completion_pending;
    size_t expected_requests;
} vireo_directory_remove_reactor_report_t;

vireo_result_t vireo_directory_remove_reactor_create(
    const vireo_auth_service_resources_t *resources, const vireo_auth_service_options_t *options,
    vireo_completion_queue_t *stat_queue, uint32_t stat_operation,
    vireo_completion_queue_t *root_queue, uint32_t root_operation,
    vireo_completion_queue_t *list_queue, uint32_t list_operation,
    size_t list_completion_bytes_per_turn,
    vireo_completion_queue_t *mkdir_queue, uint32_t mkdir_operation,
    vireo_completion_queue_t *move_queue, uint32_t move_operation,
    vireo_completion_queue_t *remove_queue, uint32_t remove_operation,
    vireo_auth_service_t **owner);

vireo_result_t vireo_directory_remove_reactor_inspect(
    const vireo_auth_service_t *service, vireo_directory_remove_reactor_report_t *out);
#endif
