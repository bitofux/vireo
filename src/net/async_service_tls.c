/* TLS有界服务：只组合公开边界，无整轮资源锁或持久owner。 */
#include "async_service_tls_internal.h"
#include <errno.h>

static vireo_result_t inspect(void *c,vireo_tcp_server_t const *s,vireo_tcp_server_info_t *r) {
    (void)c; return vireo_tcp_server_inspect(s,r);
}
static vireo_result_t pressure(void *c,vireo_tcp_server_t *s,vireo_tcp_server_tls_admission_info_t *r,
    vireo_tcp_server_listener_error_t *e) {
    (void)c; return vireo_tcp_server_tls_admission_refresh(s,r,e);
}
static vireo_result_t poll_ready(void *c,vireo_tcp_server_t *s,int timeout,size_t max,
    vireo_tcp_server_ready_client_t *ready,size_t cap,vireo_tcp_server_tls_poll_report_t *r,vireo_tcp_server_tls_error_t *e) {
    (void)c; return vireo_tcp_server_tls_poll_ready_once(s,timeout,max,ready,cap,r,e);
}
static vireo_result_t dispatch(void *c,vireo_tcp_server_t *s,vireo_event_loop_handle_t h,vireo_notifier_t *n,
    vireo_inflight_store_t *store,vireo_completion_queue_t *q,size_t max,size_t frame,size_t batch,
    uint8_t *scratch,size_t cap,vireo_completion_response_resolve_fn resolve,void *context,
    vireo_completion_t **owner,vireo_completion_response_dispatch_tls_report_t *r) {
    (void)c; return vireo_completion_response_dispatch_tls_ready(s,h,n,store,q,max,frame,batch,
        scratch,cap,resolve,context,owner,r);
}
static vireo_result_t clients(void *c,vireo_tcp_server_t *s,vireo_inflight_store_t *store,vireo_thread_pool_t *pool,
    size_t bytes,vireo_async_round_tls_configure_fn configure,void *context,vireo_tcp_server_ready_client_t const *ready,
    size_t count,vireo_async_round_tls_turn_t *turns,size_t cap,vireo_task_t **owner,vireo_async_round_tls_report_t *r) {
    (void)c; return vireo_async_round_tls_process_ready(s,store,pool,bytes,configure,context,ready,count,turns,cap,owner,r);
}
static vireo_result_t admit(void *c,vireo_tcp_server_t *s,vireo_tcp_server_admit_budget_t const *b,
    vireo_connection_pool_lease_t *out,size_t cap,vireo_tcp_server_tls_admit_info_t *r,vireo_tcp_server_tls_error_t *e) {
    (void)c; return vireo_tcp_server_tls_admit_batch(s,b,out,cap,r,e);
}
static vireo_async_service_tls_ops_t const default_ops={inspect,pressure,poll_ready,dispatch,clients,admit};
static bool valid_ops(vireo_async_service_tls_ops_t const *o) {
    return o && o->inspect && o->pressure && o->poll && o->dispatch && o->clients && o->admit;
}
static size_t minimum(size_t a,size_t b) { return a<b?a:b; }
static bool empty(vireo_connection_pool_lease_t c) { return c.pool_id==0 && c.slot_index==0 && c.generation==0; }
static vireo_result_t finish(vireo_result_t result,vireo_async_service_tls_report_t value,
    vireo_async_service_tls_report_t *out,int saved) {
    if(result==VIREO_OK) value.stage=VIREO_ASYNC_SERVICE_TLS_NONE;
    if(out) *out=value;
    errno=saved; return result;
}

vireo_result_t vireo_async_service_tls_with_ops(vireo_tcp_server_t *server,vireo_inflight_store_t *store,
    vireo_thread_pool_t *pool,vireo_notifier_t *notifier,vireo_completion_queue_t *queue,vireo_event_loop_handle_t expected,
    vireo_async_service_tls_options_t const *options,vireo_async_service_tls_workspace_t const *workspace,
    vireo_async_round_tls_configure_fn configure,void *configure_context,vireo_completion_response_resolve_fn resolve,
    void *resolve_context,vireo_task_t **task_owner,vireo_completion_t **completion_owner,
    vireo_async_service_tls_report_t *out,vireo_async_service_tls_ops_t const *ops,void *ops_context) {
    int const saved=errno; vireo_async_service_tls_report_t value={0};
    if(!server || !store || !pool || !notifier || !queue || !options || !workspace || !configure || !resolve ||
        !task_owner || !completion_owner || !out || !valid_ops(ops))
        return finish(VIREO_RESULT_INVALID_ARGUMENT,value,out,saved);
    vireo_async_service_tls_options_t const o=*options;
    vireo_async_service_tls_workspace_t const w=*workspace;
    if(*task_owner || *completion_owner || o.round.timeout_ms<0 || o.round.max_clients==0 || o.round.close_max_bytes==0 ||
        o.admit.max_accepts==0 || o.admit.max_accept_syscalls==0 || o.max_completion_items==0 ||
        o.max_response_batch_bytes==0 || !w.ready || !w.turns || !w.clients || !w.response_bytes ||
        w.ready_capacity==0 || w.turn_capacity==0 || w.client_capacity==0)
        return finish(VIREO_RESULT_INVALID_ARGUMENT,value,out,saved);
    value.stage=VIREO_ASYNC_SERVICE_TLS_VALIDATE;
    if(o.round.max_clients>VIREO_TCP_SERVER_MAX_CONNECTIONS || o.admit.max_accepts>VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        w.ready_capacity>VIREO_TCP_SERVER_MAX_CONNECTIONS || w.turn_capacity>VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        w.client_capacity>VIREO_TCP_SERVER_MAX_CONNECTIONS || o.max_completion_items>VIREO_INFLIGHT_COMPLETION_DRAIN_MAX_ITEMS ||
        o.max_response_frame_bytes<(size_t)VIREO_PROTOCOL_HEADER_SIZE ||
        o.max_response_frame_bytes>VIREO_COMPLETION_RESPONSE_MAX_FRAME_BYTES ||
        o.max_response_batch_bytes>VIREO_COMPLETION_RESPONSE_DISPATCH_MAX_BATCH_BYTES ||
        o.max_response_batch_bytes<o.max_response_frame_bytes || w.response_capacity<o.max_response_frame_bytes)
        return finish(VIREO_RESULT_RANGE,value,out,saved);
    size_t const admit_limit=minimum(o.admit.max_accepts,w.client_capacity);
    for(size_t i=0;i<admit_limit;++i)
        if(!empty(w.clients[i])) return finish(VIREO_RESULT_INVALID_ARGUMENT,value,out,saved);
    if(expected.loop_id==0 && expected.token==0) return finish(VIREO_RESULT_NOT_FOUND,value,out,saved);
    if(expected.loop_id==0 || expected.token==0) return finish(VIREO_RESULT_INVALID_ARGUMENT,value,out,saved);
    vireo_tcp_server_tls_info_t tls={0};
    vireo_result_t result=vireo_tcp_server_tls_inspect(server,&tls,&value.validation_error);
    if(result!=VIREO_OK) return finish(result,value,out,saved);
    if(o.round.close_max_bytes<minimum(tls.options.io.read_capacity,VIREO_TLS_IO_SCRATCH_BYTES) ||
        o.round.close_max_bytes<minimum(tls.options.io.write_capacity,VIREO_TLS_IO_SCRATCH_BYTES))
        return finish(VIREO_RESULT_RANGE,value,out,saved);
    value.effective_max_clients=minimum(o.round.max_clients,minimum(w.ready_capacity,w.turn_capacity));
    value.stage=VIREO_ASYNC_SERVICE_TLS_CHECK_SERVER; value.entry_checked=true;
    vireo_tcp_server_info_t root={0}; result=ops->inspect(ops_context,server,&root);
    if(result!=VIREO_OK) return finish(result,value,out,saved);
    value.stopped=root.stop_requested;
    if(value.stopped) return finish(VIREO_RESULT_CANCELLED,value,out,saved);
    value.stage=VIREO_ASYNC_SERVICE_TLS_PRE_PRESSURE; value.pre_pressure_called=true;
    result=ops->pressure(ops_context,server,&value.pre_pressure,&value.pre_pressure_error);
    if(result!=VIREO_OK) return finish(result,value,out,saved);
    value.stage=VIREO_ASYNC_SERVICE_TLS_POLL; value.poll_called=true;
    result=ops->poll(ops_context,server,o.round.timeout_ms,value.effective_max_clients,w.ready,w.ready_capacity,
        &value.poll,&value.poll_error);
    if(result!=VIREO_OK) goto post;
    if(value.poll.poll.selected_count>value.effective_max_clients) { result=VIREO_RESULT_INTERNAL; goto post; }
    value.stopped=value.poll.poll.stopped;
    if(value.stopped) { result=VIREO_RESULT_CANCELLED; goto post; }
    value.stage=VIREO_ASYNC_SERVICE_TLS_LISTENER_EVENT;
    uint32_t const events=value.poll.listener_events;
    if((events&(VIREO_EPOLL_EVENT_ERROR|VIREO_EPOLL_EVENT_HANGUP))!=0) { result=VIREO_RESULT_IO; goto post; }
    if((events&~(uint32_t)(VIREO_EPOLL_EVENT_READ|VIREO_EPOLL_EVENT_ERROR|VIREO_EPOLL_EVENT_HANGUP))!=0) {
        result=VIREO_RESULT_INTERNAL; goto post;
    }
    value.stage=VIREO_ASYNC_SERVICE_TLS_DISPATCH; value.dispatch_called=true;
    result=ops->dispatch(ops_context,server,expected,notifier,store,queue,o.max_completion_items,
        o.max_response_frame_bytes,o.max_response_batch_bytes,w.response_bytes,w.response_capacity,
        resolve,resolve_context,completion_owner,&value.dispatch);
    if(result!=VIREO_OK) goto post;
    value.stage=VIREO_ASYNC_SERVICE_TLS_CLIENTS; value.clients_called=true;
    result=ops->clients(ops_context,server,store,pool,o.round.close_max_bytes,configure,configure_context,
        w.ready,value.poll.poll.selected_count,w.turns,w.turn_capacity,task_owner,&value.clients);
    if(result!=VIREO_OK) goto post;
    if((events&VIREO_EPOLL_EVENT_READ)!=0) {
        value.stage=VIREO_ASYNC_SERVICE_TLS_CHECK_ADMISSION; value.admission_checked=true;
        result=ops->inspect(ops_context,server,&root);
        if(result!=VIREO_OK) goto post;
        value.stopped=root.stop_requested;
        if(value.stopped) { result=VIREO_RESULT_CANCELLED; goto post; }
        value.stage=VIREO_ASYNC_SERVICE_TLS_ADMIT; value.admission_called=true;
        vireo_tcp_server_admit_budget_t b=o.admit; b.max_accepts=admit_limit;
        result=ops->admit(ops_context,server,&b,w.clients,w.client_capacity,&value.admission,&value.admission_error);
    }
post:
    value.post_pressure_called=true;
    value.post_pressure_result=ops->pressure(ops_context,server,&value.post_pressure,&value.post_pressure_error);
    if(result==VIREO_OK && value.post_pressure_result!=VIREO_OK) {
        value.stage=VIREO_ASYNC_SERVICE_TLS_POST_PRESSURE; result=value.post_pressure_result;
    }
    return finish(result,value,out,saved);
}

vireo_result_t vireo_async_service_tls_once(vireo_tcp_server_t *server,vireo_inflight_store_t *store,
    vireo_thread_pool_t *pool,vireo_notifier_t *notifier,vireo_completion_queue_t *queue,
    vireo_event_loop_handle_t expected,vireo_async_service_tls_options_t const *options,
    vireo_async_service_tls_workspace_t const *workspace,vireo_async_round_tls_configure_fn configure,
    void *configure_context,vireo_completion_response_resolve_fn resolve,void *resolve_context,
    vireo_task_t **task_owner,vireo_completion_t **completion_owner,vireo_async_service_tls_report_t *report) {
    return vireo_async_service_tls_with_ops(server,store,pool,notifier,queue,expected,options,workspace,
        configure,configure_context,resolve,resolve_context,task_owner,completion_owner,report,&default_ops,NULL);
}
