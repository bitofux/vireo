/* PROJECT: VIREO; FILE: directory_root_reactor.c; DATE: 2026-10-22.
 * 同一Reactor的ROOT准入、独立关联和可恢复交付；不向网络发送VRC1。 */
#define _POSIX_C_SOURCE 200809L
#include "directory_root_reactor_internal.h"
#include <vireo/base/checked.h>
#include <errno.h>
#include <time.h>

static bool same_client(vireo_connection_pool_lease_t a,vireo_connection_pool_lease_t b)
{ return a.pool_id==b.pool_id && a.slot_index==b.slot_index && a.generation==b.generation; }
static vireo_connection_pool_lease_t client_of(vireo_task_metadata_t m)
{ return (vireo_connection_pool_lease_t){m.route.client_owner_id,m.route.client_slot_index,m.route.client_generation}; }
static bool same_request(vireo_task_metadata_t a,vireo_task_metadata_t b)
{
    bool same=false;
    return vireo_task_metadata_same_request(a,b,&same)==VIREO_OK && same;
}
static bool same_metadata(vireo_task_metadata_t a,vireo_task_metadata_t b)
{ return same_request(a,b) && a.operation==b.operation && a.deadline_ns==b.deadline_ns; }
static vireo_result_t fatal(vireo_auth_service_t *s,vireo_result_t rc)
{ if(s->infrastructure_result==VIREO_OK) s->infrastructure_result=rc; return rc; }
static vireo_result_t utc(void *c,uint64_t *out)
{
    (void)c; struct timespec t;
    if(clock_gettime(CLOCK_REALTIME,&t)) return VIREO_RESULT_IO;
    if(t.tv_sec<0 || t.tv_nsec<0 || t.tv_nsec>=1000000000L) return VIREO_RESULT_INTERNAL;
    if((uintmax_t)t.tv_sec>UINT64_MAX/1000) return VIREO_RESULT_OVERFLOW;
    return vireo_checked_u64_add((uint64_t)t.tv_sec*1000,(uint64_t)t.tv_nsec/1000000,out);
}
static vireo_result_t monotonic(void *c,uint64_t *out)
{ (void)c; return vireo_clock_monotonic_now(out,NULL); }
static vireo_result_t consume(void *c,vireo_tcp_server_t *s,vireo_connection_pool_lease_t l,size_t n)
{ (void)c; return vireo_tcp_server_client_read_consume(s,l,n,NULL); }
static vireo_result_t enqueue(void *c,vireo_tcp_server_t *s,vireo_connection_pool_lease_t l,unsigned char const *b,size_t n)
{ (void)c; return vireo_tcp_server_client_write_enqueue(s,l,b,n,NULL); }
static vireo_result_t refresh(void *c,vireo_tcp_server_t *s,vireo_connection_pool_lease_t l)
{ (void)c; vireo_tcp_server_tls_flow_info_t flow; return vireo_tcp_server_client_tls_flow_refresh(s,l,&flow,NULL); }
static vireo_result_t submit(void *c,vireo_inflight_store_t *s,vireo_tcp_server_t const *server,
    vireo_thread_pool_t *pool,size_t max,vireo_task_t **task,vireo_inflight_submit_report_t *p)
{ (void)c; return vireo_inflight_store_try_submit(s,server,pool,max,task,p); }
static vireo_result_t create_task(void *c,vireo_task_metadata_t m,uint32_t operation,
    unsigned char const *wire,size_t n,vireo_mysql_node_actor_t const *actor,size_t budget,vireo_task_t **owner)
{ (void)c; return vireo_directory_root_task_create(m,operation,wire,n,actor,budget,NULL,owner); }
void vireo_root_reactor_default_ops(vireo_root_reactor_ops_t *out)
{ *out=(vireo_root_reactor_ops_t){NULL,utc,monotonic,consume,enqueue,refresh,submit,create_task}; }

static vireo_stat_expected_t *expected(vireo_auth_service_t const *s,vireo_task_metadata_t m)
{
    for(size_t i=0;i<s->expected_capacity;++i)
        if(s->expected[i].command && s->expected[i].committed && same_request(s->expected[i].metadata,m))
            return &s->expected[i];
    return NULL;
}
/** 当前完整客户的发送资格；BUSY/NOT_FOUND/CANCELLED仅表示不能继续交付。 */
static vireo_result_t transport(vireo_auth_service_t const *s,vireo_connection_pool_lease_t c)
{
    vireo_tcp_server_info_t root;
    vireo_result_t rc=vireo_tcp_server_inspect(s->r.server,&root); if(rc!=VIREO_OK) return rc;
    if(root.stop_requested) return VIREO_RESULT_CANCELLED;
    if(c.slot_index>=s->capacity || !same_client(s->slots[c.slot_index].client,c) || s->slots[c.slot_index].closing)
        return VIREO_RESULT_NOT_FOUND;
    vireo_tcp_server_client_info_t current;
    rc=vireo_tcp_server_client_inspect(s->r.server,c,&current); if(rc!=VIREO_OK) return rc;
    if(!current.connection_info.loop_attached) return VIREO_RESULT_NOT_FOUND;
    vireo_tls_connection_t *tls=NULL;
    rc=vireo_tcp_server_client_tls_borrow(s->r.server,c,&tls,NULL); if(rc!=VIREO_OK) return rc;
    vireo_tls_connection_info_t connection; vireo_tls_io_info_t io; vireo_tls_close_info_t close;
    rc=vireo_tls_connection_inspect(tls,&connection,NULL); if(rc!=VIREO_OK) return rc;
    rc=vireo_tls_connection_io_inspect(tls,&io,NULL); if(rc!=VIREO_OK) return rc;
    rc=vireo_tls_connection_close_inspect(tls,&close,NULL); if(rc!=VIREO_OK) return rc;
    return connection.handshake_state==VIREO_TLS_HANDSHAKE_ESTABLISHED && io.state==VIREO_TLS_IO_OPEN &&
        close.state==VIREO_TLS_CLOSE_NONE?VIREO_OK:VIREO_RESULT_BUSY;
}
vireo_result_t vireo_root_reactor_finish_head(vireo_auth_service_t *s,client_slot_t *slot,vireo_auth_service_report_t *p)
{
    vireo_root_head_t *h=&slot->root_head; vireo_result_t rc;
    if(h->state==1) {
        rc=s->root_ops.consume(s->root_ops.context,s->r.server,slot->client,h->frame_bytes);
        if(rc!=VIREO_OK) return fatal(s,rc);
        h->state=2;
    }
    if(h->fatal!=VIREO_OK) return fatal(s,h->fatal);
    rc=vireo_task_destroy(&slot->task); if(rc!=VIREO_OK) return fatal(s,rc);
    if(h->transferred) { *h=(vireo_root_head_t){0}; return VIREO_OK; }
    if(h->submit.record_retained) return fatal(s,VIREO_RESULT_INTERNAL);
    if(h->rejection==0) {
        vireo_node_root_response_t const response={.status=h->status,.sequence=h->sequence};
        unsigned char wire[32]; size_t n=0;
        rc=vireo_node_root_response_encode(&response,wire,sizeof(wire),&n); if(rc!=VIREO_OK) return fatal(s,rc);
        rc=s->root_ops.enqueue(s->root_ops.context,s->r.server,slot->client,wire,n);
        if(rc==VIREO_RESULT_RANGE) { s->root_report.response_blocked=p->response_blocked=true; return VIREO_OK; }
        if(rc!=VIREO_OK) return fatal(s,rc);
        h->rejection=1; ++p->rejected; ++s->root_report.rejected;
    }
    if(h->rejection==1) {
        rc=s->root_ops.refresh(s->root_ops.context,s->r.server,slot->client); if(rc!=VIREO_OK) return fatal(s,rc);
        h->rejection=2;
    }
    *h=(vireo_root_head_t){0}; return VIREO_OK;
}
vireo_result_t vireo_root_reactor_head(vireo_auth_service_t *s,client_slot_t *slot,
    vireo_connection_frame_view_t view,vireo_auth_service_report_t *p)
{
    vireo_result_t rc=transport(s,slot->client);
    if(rc!=VIREO_OK) {
        if(rc==VIREO_RESULT_BUSY || rc==VIREO_RESULT_NOT_FOUND || rc==VIREO_RESULT_CANCELLED) { vireo_auth_service_close_slot(s,slot); return rc; }
        return fatal(s,rc);
    }
    size_t index=SIZE_MAX;
    rc=vireo_stat_reactor_reserve(s,slot->client,view.header.sequence,VIREO_COMMAND_NODE_ROOT,&index);
    if(rc!=VIREO_OK) return rc;
    vireo_root_head_t *h=&slot->root_head;
    *h=(vireo_root_head_t){.state=1,.frame_bytes=view.wire_size,.sequence=view.header.sequence,.status=VIREO_STATUS_BAD_REQUEST};
    uint8_t const *wire=NULL; size_t n=0; vireo_node_root_request_t request; vireo_node_root_issue_t issue;
    rc=vireo_tcp_server_client_read_peek(s->r.server,slot->client,&wire,&n,NULL);
    if(rc!=VIREO_OK || n<view.wire_size) { h->fatal=rc==VIREO_OK?VIREO_RESULT_INTERNAL:rc; goto finish; }
    rc=vireo_node_root_request_decode(wire,view.wire_size,&request,&issue);
    if(rc==VIREO_RESULT_PROTOCOL) goto finish;
    if(rc!=VIREO_OK) { h->fatal=rc; goto finish; }
    h->status=VIREO_STATUS_UNAUTHORIZED;
    if(!request.session_handle) goto finish;
    uint64_t now=0,deadline=0,utc_ms=0; vireo_auth_session_identity_t identity;
    rc=s->root_ops.utc(s->root_ops.context,&utc_ms); if(rc!=VIREO_OK) { h->fatal=rc; goto finish; }
    rc=vireo_auth_session_lookup(s->r.sessions,slot->client,request.session_handle,utc_ms,&identity);
    if(rc==VIREO_RESULT_NOT_FOUND || rc==VIREO_RESULT_TIMEOUT || rc==VIREO_RESULT_CANCELLED) goto finish;
    if(rc!=VIREO_OK) { h->fatal=rc; goto finish; }
    h->status=VIREO_STATUS_OVERLOADED;
    size_t count=0; rc=vireo_inflight_store_count_client(s->r.store,slot->client,&count,NULL);
    if(rc!=VIREO_OK) { h->fatal=rc; goto finish; }
    if(index==SIZE_MAX || count>=s->o.max_client_requests) goto finish;
    rc=s->root_ops.monotonic(s->root_ops.context,&now);
    if(rc==VIREO_OK) rc=vireo_checked_u64_add(now,s->o.request_timeout_ns,&deadline);
    vireo_task_metadata_t metadata;
    if(rc==VIREO_OK) rc=vireo_inflight_metadata_make_next(s->r.server,slot->client,request.sequence,
        s->root_operation,deadline,&metadata,NULL);
    if(rc!=VIREO_OK) { h->fatal=rc; goto finish; }
    vireo_mysql_node_actor_t const actor={identity.user_id,identity.session_id};
    rc=s->root_ops.create_task(s->root_ops.context,metadata,s->root_operation,wire,view.wire_size,&actor,
        s->o.task_allocation_budget,&slot->task);
    if(rc==VIREO_RESULT_NO_MEMORY) { h->status=VIREO_STATUS_OVERLOADED; goto finish; }
    if(rc!=VIREO_OK) { h->fatal=rc; goto finish; }
    s->expected[index]=(vireo_stat_expected_t){.command=VIREO_COMMAND_NODE_ROOT,.metadata=metadata,.root_request=request,.actor=actor};
    rc=s->root_ops.submit(s->root_ops.context,s->r.store,s->r.server,s->r.workers,s->o.max_client_requests,&slot->task,&h->submit);
    h->transferred=h->submit.pool_report.queue_report.transferred;
    if(h->transferred || h->submit.record_retained) { s->expected[index].committed=true; ++s->expected_count; }
    if(h->transferred) { ++p->submitted; ++s->root_report.submitted; }
    if(h->transferred && slot->task) { h->fatal=VIREO_RESULT_INTERNAL; goto finish; }
    if(h->transferred || h->submit.record_retained) { if(rc!=VIREO_OK) h->fatal=rc; }
    else if(rc!=VIREO_RESULT_BUSY && rc!=VIREO_RESULT_RANGE && rc!=VIREO_RESULT_CANCELLED) h->fatal=rc==VIREO_OK?VIREO_RESULT_INTERNAL:rc;
finish:
    if(index!=SIZE_MAX && !s->expected[index].committed) s->expected[index]=(vireo_stat_expected_t){0};
    return vireo_root_reactor_finish_head(s,slot,p);
}

static bool matches(vireo_stat_expected_t const *e,vireo_directory_root_completion_outcome_t const *o)
{
    return e && e->command==VIREO_COMMAND_NODE_ROOT && same_metadata(e->metadata,o->metadata.request) &&
        e->root_request.sequence==o->response.sequence && e->root_request.session_handle==o->request_session_handle &&
        e->actor.user_id==o->actor.user_id && e->actor.session_id==o->actor.session_id;
}
static vireo_result_t delivered(void *context,vireo_completion_t const *completion,vireo_inflight_completion_match_t match)
{
    (void)completion; vireo_root_receipt_t *r=context; r->match=match; r->state=1;
    return VIREO_RESULT_BUSY; /* 有意保owner：已take，后续绝不再次generic consume。 */
}
vireo_result_t vireo_root_reactor_discard(vireo_auth_service_t *s)
{
    if(!s->root_completion) return VIREO_OK;
    vireo_completion_info_t info; vireo_result_t rc=vireo_completion_inspect(s->root_completion,&info);
    if(rc!=VIREO_OK) return rc;
    rc=vireo_completion_destroy(&s->root_completion);
    if(!s->root_completion) { vireo_stat_reactor_forget(s,info.metadata.request); s->root_receipt=(vireo_root_receipt_t){0}; }
    return rc;
}
/** 独立receipt每次首次enqueue重核当前身份；入FIFO后只补refresh/destroy。 */
static vireo_result_t send_pending(vireo_auth_service_t *s,vireo_auth_service_report_t *p)
{
    vireo_root_receipt_t *r=&s->root_receipt;
    vireo_directory_root_completion_outcome_t const *o=&r->outcome;
    vireo_connection_pool_lease_t const client=client_of(o->metadata.request); vireo_result_t rc;
    if(client.slot_index<s->capacity && same_client(s->slots[client.slot_index].client,client)) {
        client_slot_t *slot=&s->slots[client.slot_index];
        rc=vireo_auth_deadline_guard(s,slot,p); if(rc!=VIREO_OK) return rc;
        if(slot->closing) { ++s->root_report.late_discarded; return vireo_root_reactor_discard(s); }
    }
    if(r->state==1) {
        if(!matches(expected(s,o->metadata.request),o) || !same_metadata(r->match.metadata,o->metadata.request)) return VIREO_RESULT_INTERNAL;
        rc=transport(s,client);
        if(rc==VIREO_RESULT_NOT_FOUND || rc==VIREO_RESULT_CANCELLED || rc==VIREO_RESULT_BUSY) { r->state=3; ++s->root_report.late_discarded; }
        else if(rc!=VIREO_OK) return rc;
        if(r->state==1) {
            uint64_t utc_ms=0,now=0;
            rc=s->root_ops.utc(s->root_ops.context,&utc_ms); if(rc!=VIREO_OK) return rc;
            rc=s->root_ops.monotonic(s->root_ops.context,&now); if(rc!=VIREO_OK) return rc;
            vireo_auth_session_identity_t identity;
            rc=vireo_auth_session_lookup(s->r.sessions,client,o->request_session_handle,utc_ms,&identity);
            if(rc==VIREO_RESULT_NOT_FOUND || rc==VIREO_RESULT_TIMEOUT || rc==VIREO_RESULT_CANCELLED ||
               (rc==VIREO_OK && (identity.user_id!=o->actor.user_id || identity.session_id!=o->actor.session_id))) {
                ++s->root_report.identity_discarded; r->state=3;
                rc=vireo_tcp_server_schedule_client(s->r.server,client,NULL); if(rc!=VIREO_OK) return rc;
            } else if(rc!=VIREO_OK) return rc;
            if(r->state==1) {
                bool const expired=now>=o->metadata.request.deadline_ns;
                vireo_node_root_response_t response=o->response;
                if(expired) response=(vireo_node_root_response_t){.sequence=o->response.sequence,.status=VIREO_STATUS_TIMEOUT};
                unsigned char wire[VIREO_NODE_ROOT_RESPONSE_FRAME_MAX]; size_t n=0;
                rc=vireo_node_root_response_encode(&response,wire,sizeof(wire),&n); if(rc!=VIREO_OK) return rc;
                rc=s->root_ops.enqueue(s->root_ops.context,s->r.server,client,wire,n);
                if(rc==VIREO_RESULT_RANGE) { s->root_report.response_blocked=p->response_blocked=true; return VIREO_OK; }
                if(rc!=VIREO_OK) return rc;
                r->state=2; if(expired) ++s->root_report.deadline_downgraded;
            }
        }
    }
    if(r->state==2) {
        rc=s->root_ops.refresh(s->root_ops.context,s->r.server,client); if(rc!=VIREO_OK) return rc;
        r->state=3;
        rc=vireo_tcp_server_schedule_client(s->r.server,client,NULL); if(rc!=VIREO_OK) return rc;
    }
    return r->state==3?vireo_root_reactor_discard(s):VIREO_OK;
}
vireo_result_t vireo_root_reactor_completions(vireo_auth_service_t *s,vireo_auth_service_report_t *p)
{
    vireo_result_t rc;
    for(size_t i=0;i<s->o.max_completions;++i) {
        if(!s->root_completion) {
            vireo_completion_queue_transfer_report_t transfer;
            rc=vireo_completion_queue_try_pop(s->root_queue,&s->root_completion,&transfer);
            if(!transfer.transferred && (rc==VIREO_RESULT_NOT_FOUND || rc==VIREO_RESULT_CANCELLED)) return VIREO_OK;
            if(!transfer.transferred && rc==VIREO_RESULT_BUSY) break;
            if(rc!=VIREO_OK) return rc;
        }
        if(!s->root_receipt.state) {
            vireo_directory_root_completion_outcome_t outcome;
            rc=vireo_directory_root_completion_decode(s->root_completion,s->root_operation,&outcome); if(rc!=VIREO_OK) return rc;
            vireo_inflight_completion_match_t match; vireo_inflight_stage_t stage;
            rc=vireo_inflight_store_check_completion(s->r.store,s->r.server,s->root_completion,&match,&stage);
            if(rc==VIREO_OK) {
                if(!matches(expected(s,outcome.metadata.request),&outcome)) return VIREO_RESULT_INTERNAL;
            } else if(rc!=VIREO_RESULT_NOT_FOUND || (stage!=VIREO_INFLIGHT_CHECK_CLIENT && stage!=VIREO_INFLIGHT_CHECK_RECORD)) return rc;
            s->root_receipt.outcome=outcome;
            vireo_inflight_completion_consume_report_t consumed;
            rc=vireo_inflight_store_consume_completion(s->r.store,s->r.server,&s->root_completion,delivered,&s->root_receipt,&consumed);
            if(!(rc==VIREO_RESULT_BUSY && consumed.delivery_called && consumed.record_consumed && s->root_receipt.state==1)) {
                if(!s->root_completion) { vireo_stat_reactor_forget(s,outcome.metadata.request); s->root_receipt=(vireo_root_receipt_t){0}; }
                if(rc!=VIREO_OK) return rc;
                ++s->root_report.late_discarded;
            }
        }
        if(s->root_completion) { rc=send_pending(s,p); if(rc!=VIREO_OK) return rc; }
        if(s->root_completion) return VIREO_OK; /* 本类阻塞，外层仍驱动另一queue。 */
        ++s->root_report.completions; ++p->completions;
    }
    vireo_notifier_notify_outcome_t notified; return vireo_notifier_notify(s->r.notifier,&notified,NULL);
}
