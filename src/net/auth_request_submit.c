#include "auth_request_submit_internal.h"
#include <errno.h>
#include <string.h>

/* 单次安全点观察；结束全部TLS借用后，调用者才可进入后续阶段。 */
static vireo_result_t ready_public(void *context, vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_tls_error_t *lookup_error,
    vireo_tls_connection_error_t *tls_error) {
    (void)context;
    vireo_tcp_server_info_t root;
    vireo_result_t rc = vireo_tcp_server_inspect(server, &root);
    if (rc != VIREO_OK) return rc;
    if (root.processing_active || root.driving_active || root.scheduling_active ||
        root.serving_active || root.shutdown_active || root.closing_active)
        return VIREO_RESULT_BUSY;
    if (root.stop_requested) return VIREO_RESULT_CANCELLED;
    vireo_tls_connection_t *tls = NULL;
    rc = vireo_tcp_server_client_tls_borrow(server, client, &tls, lookup_error);
    if (rc != VIREO_OK) return rc;
    vireo_tls_connection_info_t connection;
    rc = vireo_tls_connection_inspect(tls, &connection, tls_error);
    if (rc != VIREO_OK) return rc;
    vireo_tls_io_info_t io;
    rc = vireo_tls_connection_io_inspect(tls, &io, tls_error);
    if (rc != VIREO_OK) return rc;
    vireo_tls_close_info_t close;
    rc = vireo_tls_connection_close_inspect(tls, &close, tls_error);
    if (rc != VIREO_OK) return rc;
    return connection.handshake_state == VIREO_TLS_HANDSHAKE_ESTABLISHED &&
        io.state == VIREO_TLS_IO_OPEN && close.state == VIREO_TLS_CLOSE_NONE ? VIREO_OK : VIREO_RESULT_BUSY;
}

static vireo_result_t peer_public(void *context, vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, vireo_connection_peer_t *peer,
    vireo_tcp_server_client_error_t *error) {
    (void)context;
    return vireo_tcp_server_client_peer_query(server, client, peer, error);
}

static vireo_result_t submit_public(void *context, vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, vireo_inflight_store_t *store, vireo_thread_pool_t *pool,
    uint8_t const *wire, size_t size, size_t cap, size_t allocation, size_t limit,
    uint32_t operation, uint64_t deadline, vireo_task_cancel_t *cancel, vireo_task_t **task,
    vireo_async_request_report_t *report) {
    (void)context;
    return vireo_async_request_copy_try_submit(server, client, store, pool, wire, size, cap,
        allocation, limit, operation, deadline, cancel, task, report);
}

static vireo_auth_request_submit_ops_t const default_ops = {ready_public, peer_public, submit_public};

static vireo_result_t finish(vireo_result_t rc, vireo_auth_request_submit_stage_t stage,
    vireo_auth_request_submit_report_t value, vireo_auth_request_submit_report_t *report,
    int saved_errno) {
    value.stage = stage;
    if (report != NULL) *report = value;
    errno = saved_errno;
    return rc;
}

vireo_result_t vireo_auth_request_submit_with(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_inflight_store_t *store, vireo_thread_pool_t *pool,
    vireo_auth_login_admission_t *admission, vireo_monotonic_ns_t now, vireo_auth_sessions_t *sessions, uint64_t utc,
    uint8_t const *wire, size_t wire_size, vireo_auth_request_submit_options_t const *options,
    vireo_task_cancel_t *cancel, vireo_task_t **remaining_task,
    vireo_auth_request_submit_report_t *report, vireo_auth_request_submit_ops_t const *ops,
    void *context) {
    int const saved_errno = errno;
    vireo_auth_request_submit_report_t value = {0};
    if (server == NULL || store == NULL || pool == NULL || admission == NULL || sessions == NULL || wire == NULL ||
        options == NULL || remaining_task == NULL || report == NULL || ops == NULL ||
        ops->ready == NULL || ops->peer == NULL || ops->submit == NULL || *remaining_task != NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_AUTH_REQUEST_SUBMIT_NONE, value, report, saved_errno);
    vireo_auth_request_submit_options_t const o = *options;
    if (o.task_allocation_budget == 0 || o.max_client_requests == 0 || o.register_operation == 0 ||
        o.login_operation == 0 || !o.logout_operation || !o.resume_operation ||
        o.register_operation==o.login_operation || o.register_operation==o.logout_operation ||
        o.register_operation==o.resume_operation || o.login_operation==o.logout_operation ||
        o.login_operation==o.resume_operation || o.logout_operation==o.resume_operation)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_AUTH_REQUEST_SUBMIT_NONE, value, report, saved_errno);
    if (o.task_allocation_budget > VIREO_TASK_MAX_ALLOCATION_BYTES)
        return finish(VIREO_RESULT_RANGE, VIREO_AUTH_REQUEST_SUBMIT_NONE, value, report, saved_errno);
    vireo_auth_request_view_t request;
    vireo_result_t rc = vireo_auth_request_decode(wire, wire_size, &request, &value.request_issue);
    if (rc != VIREO_OK)
        return finish(rc, VIREO_AUTH_REQUEST_SUBMIT_DECODE, value, report, saved_errno);
    value.input_validated = true;
    value.command = request.command; value.sequence = request.sequence; value.frame_bytes = wire_size;
    value.transport_called = true;
    rc = ops->ready(context, server, client, &value.lookup_error, &value.tls_error);
    if (rc != VIREO_OK)
        return finish(rc, VIREO_AUTH_REQUEST_SUBMIT_TRANSPORT, value, report, saved_errno);
    value.transport_ready = true;
    bool const login = request.command == VIREO_COMMAND_LOGIN;
    if (login) {
        value.peer_called = true;
        rc = ops->peer(context, server, client, &value.peer, &value.peer_error);
        if (rc != VIREO_OK)
            return finish(rc, VIREO_AUTH_REQUEST_SUBMIT_PEER, value, report, saved_errno);
        vireo_auth_login_peer_t peer = {.family = value.peer.family};
        memcpy(peer.address, value.peer.address, sizeof(peer.address));
        value.admission_called = true;
        rc = vireo_auth_login_admission_check(admission, now, &peer,
            (char const *)request.username, request.username_size, request.device, &value.decision);
        if (rc != VIREO_OK)
            return finish(rc, VIREO_AUTH_REQUEST_SUBMIT_ADMISSION, value, report, saved_errno);
        value.admission_decided = true;
        if (value.decision.outcome != VIREO_RATE_LIMIT_ADMITTED)
            return finish(VIREO_RESULT_BUSY, VIREO_AUTH_REQUEST_SUBMIT_ADMISSION, value, report, saved_errno);
        value.login_charged = true;
    }
    bool const logout=request.command==VIREO_COMMAND_LOGOUT;
    bool const resume=request.command==VIREO_COMMAND_SESSION_RESUME;
    vireo_auth_session_identity_t identity={0};
    if(logout) {
        value.session_checked=true;
        rc=vireo_auth_session_lookup(sessions,client,request.session_handle,utc,&identity);
        if(rc!=VIREO_OK) return finish(rc,VIREO_AUTH_REQUEST_SUBMIT_SESSION,value,report,saved_errno);
    }
    value.task_payload_bytes=logout?56:wire_size;
    value.submit_called = true;
    if(logout || resume) {
        vireo_async_request_report_t *a=&value.submit_report;
        a->input_validated=true; a->frame_bytes=wire_size;
        rc=vireo_inflight_metadata_make_next(server,client,request.sequence,
            logout?o.logout_operation:o.resume_operation,o.deadline_ns,&a->metadata,&a->inflight_stage);
        a->metadata_created=rc==VIREO_OK;
        if(rc==VIREO_OK && resume) rc=vireo_auth_session_note_resume(sessions,a->metadata.request_instance_id);
        if(rc==VIREO_OK) {
            vireo_auth_logout_identity_t const target={identity.user_id,identity.session_id};
            rc=logout?vireo_auth_task_create_logout(a->metadata,o.logout_operation,wire,wire_size,&target,
                    o.task_allocation_budget,cancel,remaining_task):
                cancel?vireo_task_create_copy_with_cancel(a->metadata,wire,wire_size,o.task_allocation_budget,cancel,remaining_task):
                    vireo_task_create_copy(a->metadata,wire,wire_size,o.task_allocation_budget,remaining_task);
            a->task_created=rc==VIREO_OK; value.trusted_identity_attached=logout && a->task_created;
        }
        if(rc==VIREO_OK) {
            a->submit_called=true;
            rc=vireo_inflight_store_try_submit(store,server,pool,o.max_client_requests,remaining_task,&a->submit_report);
            a->task_transferred=a->submit_report.pool_report.queue_report.transferred;
        }
        a->task_retained=*remaining_task!=NULL;
        a->stage=rc==VIREO_OK?VIREO_ASYNC_REQUEST_NONE:!a->metadata_created?VIREO_ASYNC_REQUEST_MAKE_METADATA:
            !a->task_created?VIREO_ASYNC_REQUEST_CREATE_TASK:VIREO_ASYNC_REQUEST_SUBMIT;
    } else rc = ops->submit(context, server, client, store, pool, wire, wire_size,
        VIREO_AUTH_REQUEST_FRAME_MAX, o.task_allocation_budget, o.max_client_requests,
        login ? o.login_operation : o.register_operation, o.deadline_ns, cancel, remaining_task,
        &value.submit_report);
    return finish(rc, rc == VIREO_OK ? VIREO_AUTH_REQUEST_SUBMIT_NONE : VIREO_AUTH_REQUEST_SUBMIT_QUEUE,
        value, report, saved_errno);
}

vireo_result_t vireo_auth_request_copy_try_submit(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_inflight_store_t *store, vireo_thread_pool_t *pool,
    vireo_auth_login_admission_t *admission, vireo_monotonic_ns_t now, vireo_auth_sessions_t *sessions, uint64_t utc,
    uint8_t const *wire, size_t wire_size, vireo_auth_request_submit_options_t const *options,
    vireo_task_cancel_t *cancel, vireo_task_t **remaining_task,
    vireo_auth_request_submit_report_t *report) {
    return vireo_auth_request_submit_with(server, client, store, pool, admission, now, sessions, utc, wire, wire_size,
        options, cancel, remaining_task, report, &default_ops, NULL);
}
