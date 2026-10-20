/* PROJECT: VIREO; FILE: auth_response_consumer.c; AUTHOR: bitofux; DATE: 2026-10-20. */
#include "auth_response_consumer_internal.h"
#include <vireo/base/secure_clear.h>
#include <errno.h>
#include <string.h>
_Static_assert(VIREO_AUTH_RESPONSE_TOKEN_BYTES == sizeof(((vireo_session_token_t *)0)->bytes), "token width");
static vireo_result_t enqueue_native(void *c, vireo_tcp_server_t *s,
    vireo_connection_pool_lease_t l, unsigned char const *p, size_t n, vireo_tcp_server_client_error_t *e)
{ (void)c; return vireo_tcp_server_client_write_enqueue(s, l, p, n, e); }
static vireo_result_t refresh_native(void *c, vireo_tcp_server_t *s, vireo_connection_pool_lease_t l,
    vireo_tcp_server_tls_flow_info_t *i, vireo_tcp_server_tls_application_error_t *e)
{ (void)c; return vireo_tcp_server_client_tls_flow_refresh(s, l, i, e); }
static vireo_auth_response_consumer_ops_t const defaults = {enqueue_native, refresh_native};
static bool metadata_same(vireo_task_metadata_t a, vireo_task_metadata_t b)
{
    bool same = false;
    return vireo_task_metadata_same_request(a, b, &same) == VIREO_OK && same &&
        a.operation == b.operation && a.deadline_ns == b.deadline_ns;
}
static vireo_connection_pool_lease_t client_of(vireo_task_metadata_t m)
{ return (vireo_connection_pool_lease_t){m.route.client_owner_id, m.route.client_slot_index, m.route.client_generation}; }
static vireo_result_t ready(vireo_tcp_server_t *server, vireo_connection_pool_lease_t client,
    bool before_enqueue, vireo_auth_response_consumer_report_t *report)
{
    vireo_tcp_server_info_t root; vireo_result_t rc = vireo_tcp_server_inspect(server, &root);
    if (rc != VIREO_OK) return rc;
    if (root.processing_active || root.driving_active || root.scheduling_active || root.serving_active ||
        root.shutdown_active || root.closing_active) return VIREO_RESULT_BUSY;
    if (before_enqueue && root.stop_requested) return VIREO_RESULT_CANCELLED;
    vireo_tcp_server_client_info_t current;
    rc = vireo_tcp_server_client_inspect(server, client, &current); if (rc != VIREO_OK) return rc;
    if (!current.connection_info.loop_attached) return VIREO_RESULT_NOT_FOUND;
    vireo_tls_connection_t *tls = NULL;
    rc = vireo_tcp_server_client_tls_borrow(server, client, &tls, &report->lookup_error); if (rc != VIREO_OK) return rc;
    if (!before_enqueue) return VIREO_OK;
    vireo_tls_connection_info_t connection;
    rc = vireo_tls_connection_inspect(tls, &connection, &report->tls_error.tls_error); if (rc != VIREO_OK) return rc;
    vireo_tls_io_info_t io;
    rc = vireo_tls_connection_io_inspect(tls, &io, &report->tls_error.tls_error); if (rc != VIREO_OK) return rc;
    vireo_tls_close_info_t close;
    rc = vireo_tls_connection_close_inspect(tls, &close, &report->tls_error.tls_error); if (rc != VIREO_OK) return rc;
    return connection.handshake_state == VIREO_TLS_HANDSHAKE_ESTABLISHED &&
        io.state == VIREO_TLS_IO_OPEN && close.state == VIREO_TLS_CLOSE_NONE ? VIREO_OK : VIREO_RESULT_BUSY;
}

/* 在客户匹配/丢弃之前应用全服务效果；receipt不持秘密或网络借用。 */
static vireo_result_t effects(vireo_auth_sessions_t *sessions,vireo_auth_completion_outcome_t const *o,
    vireo_auth_response_consumer_receipt_t *r)
{
    if(r->effect_applied) return metadata_same(r->effect_metadata.request,o->metadata.request) &&
        r->effect_metadata.result==o->metadata.result && r->effect_metadata.suggested_status==o->metadata.suggested_status &&
        r->effect_target.user_id==o->logout_target.user_id && r->effect_target.session_id==o->logout_target.session_id?
            VIREO_OK:VIREO_RESULT_INVALID_ARGUMENT;
    if(o->command!=VIREO_COMMAND_LOGOUT || o->commit==VIREO_AUTH_NOT_COMMITTED) return VIREO_OK;
    vireo_result_t const rc=vireo_auth_session_apply_logout(sessions,o->logout_target.session_id);
    if(rc!=VIREO_OK) return rc;
    r->effect_applied=true; r->effect_metadata=o->metadata; r->effect_target=o->logout_target;
    return VIREO_OK;
}

typedef struct delivery {
    vireo_tcp_server_t *server;
    vireo_auth_sessions_t *sessions;
    vireo_auth_completion_outcome_t const *outcome;
    uint64_t now;
    vireo_auth_response_consumer_receipt_t *receipt;
    vireo_auth_response_consumer_report_t *report;
    vireo_auth_response_consumer_ops_t const *ops;
    void *context;
} delivery_t;
static vireo_result_t send_result(delivery_t *d)
{
    vireo_auth_response_consumer_receipt_t *r = d->receipt;
    vireo_auth_response_consumer_report_t *p = d->report;
    vireo_auth_completion_outcome_t const *o = d->outcome;
    vireo_connection_pool_lease_t const client = client_of(r->metadata.request);
    unsigned char wire[104] = {0}; vireo_auth_response_t response = {0};
    vireo_result_t rc = VIREO_OK;
    if (r->state == VIREO_AUTH_CONSUMER_NEEDS_ENQUEUE) {
        p->stage = VIREO_AUTH_CONSUMER_TRANSPORT;
        rc = ready(d->server, client, true, p); if (rc != VIREO_OK) goto done;
        bool const resume=o->command==VIREO_COMMAND_SESSION_RESUME && o->resume_validated;
        bool const login = (o->command == VIREO_COMMAND_LOGIN && o->commit == VIREO_AUTH_COMMITTED) || resume;
        if(resume && r->wire_status==VIREO_STATUS_OK) {
            rc=vireo_auth_session_check_resume(d->sessions,o->metadata.request.request_instance_id);
            if(rc==VIREO_RESULT_BUSY) r->wire_status=VIREO_STATUS_BUSY;
            else if(rc!=VIREO_OK) goto done;
            if(d->now<o->issued_at_ms || d->now>=o->expires_at_ms) r->wire_status=VIREO_STATUS_AUTHENTICATION_FAILED;
        }
        if(resume && r->wire_status!=VIREO_STATUS_OK && r->ticket_pending) {
            rc=vireo_auth_session_abort(d->sessions,r->ticket); if(rc!=VIREO_OK) goto done;
            r->ticket_pending=false; r->ticket=(vireo_auth_session_ticket_t){0};
        }
        if (login && !resume && d->now >= o->expires_at_ms) {
            if (r->ticket_pending) {
                rc = vireo_auth_session_abort(d->sessions, r->ticket); if (rc != VIREO_OK) goto done;
                r->ticket_pending = false; r->ticket = (vireo_auth_session_ticket_t){0};
            }
            r->wire_status = VIREO_STATUS_SESSION_EXPIRED;
        }
        if (login && r->wire_status == VIREO_STATUS_OK && !r->ticket_pending) {
            p->stage = VIREO_AUTH_CONSUMER_RESERVE;
            vireo_auth_session_identity_t const identity = {o->user_id, o->session_id, o->issued_at_ms, o->expires_at_ms, false};
            rc = vireo_auth_session_reserve(d->sessions, client, &identity, &r->ticket); if (rc != VIREO_OK) goto done;
            r->ticket_pending = true;
        }
        response.command = o->command; response.sequence = o->metadata.request.route.request_sequence;
        response.status = r->wire_status;
        if (response.status == VIREO_STATUS_OK) {
            response.user_id = o->user_id; response.root_node_id = o->root_node_id;
            if (login) {
                response.session_handle = r->ticket.handle; response.issued_at_ms = o->issued_at_ms;
                response.expires_at_ms = o->expires_at_ms; if(!resume) memcpy(response.token, o->token.bytes, 32);
            }
        }
        p->stage = VIREO_AUTH_CONSUMER_ENCODE;
        rc = vireo_auth_response_encode(&response, wire, sizeof(wire), &p->frame_bytes); if (rc != VIREO_OK) goto done;
        p->frame_encoded = true; p->enqueue_called = true; p->stage = VIREO_AUTH_CONSUMER_ENQUEUE;
        rc = d->ops->enqueue(d->context, d->server, client, wire, p->frame_bytes, &p->enqueue_error);
        if (rc != VIREO_OK) goto done;
        p->enqueued = true;
        r->state = r->ticket_pending ? VIREO_AUTH_CONSUMER_NEEDS_BIND : VIREO_AUTH_CONSUMER_NEEDS_REFRESH;
    }
    if (r->state == VIREO_AUTH_CONSUMER_NEEDS_BIND) {
        p->stage = VIREO_AUTH_CONSUMER_BIND;
        rc = vireo_auth_session_commit(d->sessions, r->ticket); if (rc != VIREO_OK) goto done;
        r->ticket_pending = false; p->bound = true; r->state = VIREO_AUTH_CONSUMER_NEEDS_REFRESH;
    }
    if (r->state == VIREO_AUTH_CONSUMER_NEEDS_REFRESH) {
        p->stage = VIREO_AUTH_CONSUMER_TRANSPORT;
        rc = ready(d->server, client, false, p); if (rc != VIREO_OK) goto done;
        p->refresh_called = true; p->stage = VIREO_AUTH_CONSUMER_REFRESH;
        rc = d->ops->refresh(d->context, d->server, client, &p->flow, &p->tls_error); if (rc != VIREO_OK) goto done;
        r->state = VIREO_AUTH_CONSUMER_READY;
    }
    p->stage = VIREO_AUTH_CONSUMER_NONE;
done:
    (void)vireo_secure_clear(wire, sizeof(wire)); (void)vireo_auth_response_clear(&response); return rc;
}
/* 028已经take；先保存恢复快照，然后才执行任何可失败发送步骤。 */
static vireo_result_t deliver(void *context, vireo_completion_t const *completion, vireo_inflight_completion_match_t match)
{
    (void)completion; delivery_t *d = context;
    d->receipt->match = match; d->receipt->metadata = d->outcome->metadata;
    d->receipt->command = d->outcome->command;
    d->receipt->wire_status = d->outcome->metadata.suggested_status;
    d->receipt->state = VIREO_AUTH_CONSUMER_NEEDS_ENQUEUE;
    return send_result(d);
}

vireo_result_t vireo_auth_response_consumer_with(vireo_tcp_server_t *server,
    vireo_inflight_store_t *store, vireo_auth_sessions_t *sessions, vireo_completion_t **owner,
    vireo_auth_response_consumer_options_t const *options, uint64_t now,
    vireo_auth_response_consumer_receipt_t *receipt, vireo_auth_response_consumer_report_t *report,
    vireo_auth_response_consumer_ops_t const *ops, void *context)
{
    int const saved_errno = errno; vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_auth_response_consumer_report_t p = {0}; vireo_auth_completion_outcome_t o = {0};
    if (server == NULL || store == NULL || sessions == NULL || owner == NULL || options == NULL ||
        receipt == NULL || report == NULL || ops == NULL || ops->enqueue == NULL || ops->refresh == NULL ||
        options->register_operation == 0 || options->login_operation == 0 ||
        options->register_operation == options->login_operation || !options->logout_operation || !options->resume_operation ||
        options->register_operation==options->logout_operation || options->register_operation==options->resume_operation ||
        options->login_operation==options->logout_operation || options->login_operation==options->resume_operation ||
        options->logout_operation==options->resume_operation) goto done;
    if (receipt->state == VIREO_AUTH_CONSUMER_READY) { rc = *owner == NULL ? VIREO_OK : VIREO_RESULT_BUSY; goto done; }
    if (receipt->state < VIREO_AUTH_CONSUMER_EMPTY || receipt->state > VIREO_AUTH_CONSUMER_NEEDS_REFRESH) goto done;
    rc = VIREO_RESULT_NOT_FOUND; if (*owner == NULL) goto done;
    p.stage = VIREO_AUTH_CONSUMER_DECODE;
    rc = vireo_auth_completion_decode(*owner, &o); if (rc != VIREO_OK) goto done;
    rc = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_auth_task_options_t const registry={options->register_operation,options->login_operation,0,
        options->logout_operation,options->resume_operation};
    if(vireo_auth_task_command(&registry,o.metadata.request.operation)!=o.command) goto done;
    rc=effects(sessions,&o,receipt); if(rc!=VIREO_OK) goto done;
    rc=VIREO_RESULT_INVALID_ARGUMENT;
    delivery_t d = {server, sessions, &o, now, receipt, &p, ops, context};
    if (receipt->state == VIREO_AUTH_CONSUMER_EMPTY) {
        if (receipt->command != 0 || receipt->ticket_pending || receipt->ticket.serial != 0 ||
            receipt->metadata.request.request_instance_id != 0) goto done;
        p.consume_called = true; p.stage = VIREO_AUTH_CONSUMER_MATCH;
        rc = vireo_inflight_store_consume_completion(store, server, owner, deliver, &d, &p.consumption);
        if (!p.consumption.delivery_called && rc == VIREO_OK) {
            p.stage = VIREO_AUTH_CONSUMER_NONE;
            if (p.consumption.disposition == VIREO_INFLIGHT_COMPLETION_CLIENT_GONE)
                (void)vireo_auth_session_forget(sessions, client_of(o.metadata.request));
            if(*owner==NULL) (void)vireo_secure_clear(receipt,sizeof(*receipt));
        }
    } else {
        if (!metadata_same(receipt->metadata.request, o.metadata.request) ||
            !metadata_same(receipt->match.metadata, o.metadata.request) || receipt->command != o.command ||
            receipt->metadata.result != o.metadata.result || receipt->metadata.suggested_status != o.metadata.suggested_status ||
            (receipt->wire_status != o.metadata.suggested_status &&
             !(o.command==VIREO_COMMAND_LOGIN && receipt->wire_status==VIREO_STATUS_SESSION_EXPIRED) &&
             !(o.command==VIREO_COMMAND_SESSION_RESUME && o.resume_validated &&
               (receipt->wire_status==VIREO_STATUS_BUSY || receipt->wire_status==VIREO_STATUS_AUTHENTICATION_FAILED)))) goto done;
        rc = send_result(&d);
        if (rc == VIREO_OK) {
            p.stage = VIREO_AUTH_CONSUMER_DESTROY;
            rc = vireo_completion_destroy(owner); if (rc == VIREO_OK) p.stage = VIREO_AUTH_CONSUMER_NONE;
        }
    }
done:
    (void)vireo_auth_completion_outcome_clear(&o);
    if (receipt != NULL) p.state = receipt->state;
    if (report != NULL) *report = p;
    errno = saved_errno; return rc;
}
vireo_result_t vireo_auth_response_consumer_step(vireo_tcp_server_t *server,
    vireo_inflight_store_t *store, vireo_auth_sessions_t *sessions, vireo_completion_t **owner,
    vireo_auth_response_consumer_options_t const *options, uint64_t now,
    vireo_auth_response_consumer_receipt_t *receipt, vireo_auth_response_consumer_report_t *report)
{ return vireo_auth_response_consumer_with(server, store, sessions, owner, options, now, receipt, report, &defaults, NULL); }
vireo_result_t vireo_auth_response_consumer_acknowledge(vireo_completion_t const *owner,
    vireo_auth_response_consumer_receipt_t *receipt)
{
    if (receipt == NULL) return VIREO_RESULT_INVALID_ARGUMENT;
    if (owner != NULL || receipt->state != VIREO_AUTH_CONSUMER_READY) return VIREO_RESULT_BUSY;
    return vireo_secure_clear(receipt, sizeof(*receipt));
}
vireo_result_t vireo_auth_response_consumer_abandon(vireo_auth_sessions_t *sessions,
    vireo_completion_t **owner, vireo_auth_response_consumer_receipt_t *receipt)
{
    if (sessions == NULL || owner == NULL || receipt == NULL) return VIREO_RESULT_INVALID_ARGUMENT;
    if (receipt->state == VIREO_AUTH_CONSUMER_EMPTY && *owner==NULL) return VIREO_RESULT_NOT_FOUND;
    if (receipt->state < VIREO_AUTH_CONSUMER_EMPTY || receipt->state > VIREO_AUTH_CONSUMER_READY)
        return VIREO_RESULT_INVALID_ARGUMENT;
    if (*owner != NULL) {
        vireo_completion_info_t info;
        vireo_result_t inspected=vireo_completion_inspect(*owner,&info);
        if(inspected!=VIREO_OK) return inspected;
        if(receipt->state!=VIREO_AUTH_CONSUMER_EMPTY &&
           (!metadata_same(info.metadata.request,receipt->metadata.request) || info.metadata.result!=receipt->metadata.result ||
            info.metadata.suggested_status!=receipt->metadata.suggested_status)) return VIREO_RESULT_INVALID_ARGUMENT;
        vireo_auth_completion_outcome_t o={0};
        vireo_result_t rc=vireo_auth_completion_decode(*owner,&o);
        if(rc==VIREO_OK && receipt->state!=VIREO_AUTH_CONSUMER_EMPTY &&
           (!metadata_same(o.metadata.request,receipt->metadata.request) || o.metadata.result!=receipt->metadata.result ||
            o.metadata.suggested_status!=receipt->metadata.suggested_status)) rc=VIREO_RESULT_INVALID_ARGUMENT;
        if(rc==VIREO_OK) rc=effects(sessions,&o,receipt);
        (void)vireo_auth_completion_outcome_clear(&o);
        if(rc!=VIREO_OK) return rc;
    }
    if (receipt->ticket_pending) {
        vireo_result_t rc = vireo_auth_session_abort(sessions, receipt->ticket);
        if (rc != VIREO_OK && rc != VIREO_RESULT_NOT_FOUND) return rc;
        receipt->ticket_pending = false;
    }
    vireo_result_t rc = vireo_completion_destroy(owner);
    if (rc == VIREO_OK) rc = vireo_secure_clear(receipt, sizeof(*receipt));
    return rc;
}
