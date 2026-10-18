/* 有界TLS异步轮次，全部经公开边界组合，无长期状态。 */
#include "async_round_tls_internal.h"
#include <errno.h>

static vireo_result_t poll_ready(void *c,vireo_tcp_server_t *s,int timeout,size_t max,
    vireo_tcp_server_ready_client_t *ready,size_t cap,vireo_tcp_server_tls_poll_report_t *r,vireo_tcp_server_tls_error_t *e) {
    (void)c; return vireo_tcp_server_tls_poll_ready_once(s,timeout,max,ready,cap,r,e);
}
static vireo_result_t handshake(void *c,vireo_tcp_server_t *s,vireo_connection_pool_lease_t l,
    vireo_tcp_server_tls_handshake_info_t *r,vireo_tcp_server_tls_error_t *e) {
    (void)c; return vireo_tcp_server_client_tls_handshake_step(s,l,r,e);
}
static vireo_result_t close_step(void *c,vireo_tcp_server_t *s,vireo_connection_pool_lease_t l,size_t bytes,
    vireo_tcp_server_tls_close_step_info_t *r,vireo_tcp_server_tls_close_error_t *e) {
    (void)c; return vireo_tcp_server_client_tls_close_step(s,l,bytes,r,e);
}
static vireo_result_t drive(void *c,vireo_tcp_server_t *s,vireo_connection_pool_lease_t l,
    vireo_inflight_store_t *store,vireo_thread_pool_t *pool,vireo_async_client_drive_options_t const *o,
    vireo_async_client_drive_tls_budget_t const *b,vireo_task_cancel_t *cancel,vireo_async_request_pending_t *pending,
    vireo_task_t **owner,vireo_async_client_drive_tls_report_t *r) {
    (void)c; return vireo_async_client_drive_tls_once(s,l,store,pool,o,b,cancel,pending,owner,r);
}
static vireo_result_t schedule(void *c,vireo_tcp_server_t *s,vireo_connection_pool_lease_t l,vireo_tcp_server_client_error_t *e) {
    (void)c; return vireo_tcp_server_schedule_client(s,l,e);
}
static vireo_async_round_tls_ops_t const default_ops={poll_ready,handshake,close_step,drive,schedule};
static bool valid_ops(vireo_async_round_tls_ops_t const *o) {
    return o && o->poll && o->handshake && o->close && o->drive && o->schedule;
}
static size_t minimum(size_t a,size_t b) { return a<b?a:b; }
static vireo_result_t finish(vireo_result_t result,vireo_async_round_tls_report_t value,
    vireo_async_round_tls_report_t *out,int saved) {
    if(result==VIREO_OK) value.stage=VIREO_ASYNC_ROUND_TLS_NONE;
    if(out) *out=value;
    errno=saved; return result;
}

/** 每个被取出的客户只选择一个阶段；结束状态观察借用后再调用公开驱动。 */
static vireo_result_t dispatch(vireo_tcp_server_t *server,vireo_inflight_store_t *store,vireo_thread_pool_t *pool,
    size_t close_bytes,vireo_async_round_tls_configure_fn configure,void *context,vireo_task_t **owner,
    vireo_async_round_tls_turn_t *turn,vireo_async_round_tls_ops_t const *ops,void *ops_context) {
    turn->stage=VIREO_ASYNC_ROUND_TLS_LOOKUP;
    vireo_tls_connection_t *tls=NULL;
    vireo_result_t result=vireo_tcp_server_client_tls_borrow(server,turn->client.client,&tls,&turn->lookup_error);
    if(result!=VIREO_OK) return result;
    turn->stage=VIREO_ASYNC_ROUND_TLS_INSPECT;
    vireo_tls_connection_info_t state={0};
    result=vireo_tls_connection_inspect(tls,&state,&turn->tls_error);
    if(result!=VIREO_OK) return result;
    if(state.handshake_state<VIREO_TLS_HANDSHAKE_INITIAL || state.handshake_state>VIREO_TLS_HANDSHAKE_FAILED)
        return VIREO_RESULT_INTERNAL;
    if(state.handshake_state!=VIREO_TLS_HANDSHAKE_ESTABLISHED) {
        turn->path=VIREO_TCP_SERVER_TLS_TURN_HANDSHAKE; turn->stage=VIREO_ASYNC_ROUND_TLS_HANDSHAKE;
        turn->handshake_called=true;
        result=ops->handshake(ops_context,server,turn->client.client,&turn->handshake,&turn->handshake_error);
    } else {
        vireo_tls_close_info_t close={0}; result=vireo_tls_connection_close_inspect(tls,&close,&turn->tls_error);
        if(result!=VIREO_OK) return result;
        if(close.state<VIREO_TLS_CLOSE_NONE || close.state>VIREO_TLS_CLOSE_FAILED) return VIREO_RESULT_INTERNAL;
        if(close.state!=VIREO_TLS_CLOSE_NONE) {
            turn->path=VIREO_TCP_SERVER_TLS_TURN_CLOSE; turn->stage=VIREO_ASYNC_ROUND_TLS_CLOSE; turn->close_called=true;
            result=ops->close(ops_context,server,turn->client.client,close_bytes,&turn->close,&turn->close_error);
        } else {
            turn->path=VIREO_TCP_SERVER_TLS_TURN_APPLICATION; turn->stage=VIREO_ASYNC_ROUND_TLS_CONFIGURE;
            vireo_async_round_tls_config_t config={0}; turn->configure_called=true;
            result=configure(context,turn->client,&config); turn->configure_result=result;
            if(result!=VIREO_OK) return result;
            turn->stage=VIREO_ASYNC_ROUND_TLS_DRIVE; turn->drive_called=true;
            result=ops->drive(ops_context,server,turn->client.client,store,pool,&config.options,&config.budget,
                config.cancel,config.pending,owner,&turn->drive_report);
        }
    }
    if(result==VIREO_OK && ((turn->handshake_called && turn->handshake.application_ready) ||
        (turn->drive_called && turn->drive_report.needs_reschedule))) {
        turn->stage=VIREO_ASYNC_ROUND_TLS_SCHEDULE; turn->schedule_called=true;
        result=ops->schedule(ops_context,server,turn->client.client,&turn->schedule_error);
        turn->schedule_result=result;
    }
    return result;
}

/** 共享已选批次内核；不poll、不截断，首错保持已尝试前缀与caller后缀。 */
static vireo_result_t process_ready(vireo_tcp_server_t *server,vireo_inflight_store_t *store,
    vireo_thread_pool_t *pool,size_t close_bytes,vireo_async_round_tls_configure_fn configure,void *context,
    vireo_tcp_server_ready_client_t const *ready,size_t ready_count,vireo_async_round_tls_turn_t *turns,
    vireo_task_t **owner,vireo_async_round_tls_report_t value,vireo_async_round_tls_report_t *out,
    vireo_async_round_tls_ops_t const *ops,void *ops_context,int saved) {
    for(size_t i=0;i<ready_count;++i) {
        vireo_async_round_tls_turn_t turn={.client=ready[i]};
        vireo_result_t result=dispatch(server,store,pool,close_bytes,configure,context,owner,&turn,ops,ops_context);
        turn.result=result;
        if(result==VIREO_OK) turn.stage=VIREO_ASYNC_ROUND_TLS_NONE;
        turns[i]=turn; ++value.turn_count; value.unprocessed_begin=value.turn_count;
        if(turn.handshake_called) ++value.handshake_calls;
        if(turn.drive_called) ++value.drive_calls;
        if(turn.close_called) ++value.close_calls;
        if(turn.schedule_called && turn.schedule_result==VIREO_OK) ++value.requeued_count;
        if(result!=VIREO_OK) { value.stage=turn.stage; return finish(result,value,out,saved); }
    }
    return finish(VIREO_OK,value,out,saved);
}

vireo_result_t vireo_async_round_tls_with_ops(vireo_tcp_server_t *server,vireo_inflight_store_t *store,
    vireo_thread_pool_t *pool,vireo_async_round_tls_options_t const *options,
    vireo_async_round_tls_configure_fn configure,void *context,vireo_tcp_server_ready_client_t *ready,
    size_t ready_capacity,vireo_async_round_tls_turn_t *turns,size_t turn_capacity,vireo_task_t **owner,
    vireo_async_round_tls_report_t *out,vireo_async_round_tls_ops_t const *ops,void *ops_context) {
    int const saved=errno; vireo_async_round_tls_report_t value={0};
    if(!server || !store || !pool || !options || !configure || !ready || !turns || !owner || !out || !valid_ops(ops) || *owner)
        return finish(VIREO_RESULT_INVALID_ARGUMENT,value,out,saved);
    vireo_async_round_tls_options_t const o=*options;
    if(o.timeout_ms<0 || o.max_clients==0 || ready_capacity==0 || turn_capacity==0 || o.close_max_bytes==0)
        return finish(VIREO_RESULT_INVALID_ARGUMENT,value,out,saved);
    if(o.max_clients>VIREO_TCP_SERVER_MAX_CONNECTIONS || ready_capacity>VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        turn_capacity>VIREO_TCP_SERVER_MAX_CONNECTIONS) return finish(VIREO_RESULT_RANGE,value,out,saved);
    value.stage=VIREO_ASYNC_ROUND_TLS_VALIDATE;
    vireo_tcp_server_tls_info_t root={0}; vireo_result_t result=vireo_tcp_server_tls_inspect(server,&root,&value.validation_error);
    if(result!=VIREO_OK) return finish(result,value,out,saved);
    if(o.close_max_bytes<minimum(root.options.io.read_capacity,VIREO_TLS_IO_SCRATCH_BYTES) ||
        o.close_max_bytes<minimum(root.options.io.write_capacity,VIREO_TLS_IO_SCRATCH_BYTES))
        return finish(VIREO_RESULT_RANGE,value,out,saved);
    value.effective_max_clients=minimum(o.max_clients,minimum(ready_capacity,turn_capacity));
    value.stage=VIREO_ASYNC_ROUND_TLS_POLL; value.poll_called=true;
    result=ops->poll(ops_context,server,o.timeout_ms,value.effective_max_clients,ready,ready_capacity,
        &value.poll_report,&value.poll_error); value.poll_result=result;
    if(result!=VIREO_OK) return finish(result,value,out,saved);
    /* 公开poll保证上限；own替身违约时不越caller数组，也不消费伪造ready。 */
    if(value.poll_report.poll.selected_count>value.effective_max_clients)
        return finish(VIREO_RESULT_INTERNAL,value,out,saved);
    return process_ready(server,store,pool,o.close_max_bytes,configure,context,ready,
        value.poll_report.poll.selected_count,turns,owner,value,out,ops,ops_context,saved);
}

vireo_result_t vireo_async_round_tls_once(vireo_tcp_server_t *server,vireo_inflight_store_t *store,
    vireo_thread_pool_t *pool,vireo_async_round_tls_options_t const *options,
    vireo_async_round_tls_configure_fn configure,void *context,vireo_tcp_server_ready_client_t *ready,
    size_t ready_capacity,vireo_async_round_tls_turn_t *turns,size_t turn_capacity,vireo_task_t **owner,
    vireo_async_round_tls_report_t *report) {
    return vireo_async_round_tls_with_ops(server,store,pool,options,configure,context,ready,ready_capacity,
        turns,turn_capacity,owner,report,&default_ops,NULL);
}

vireo_result_t vireo_async_round_tls_process_ready(vireo_tcp_server_t *server,vireo_inflight_store_t *store,
    vireo_thread_pool_t *pool,size_t close_bytes,vireo_async_round_tls_configure_fn configure,void *context,
    vireo_tcp_server_ready_client_t const *ready,size_t ready_count,vireo_async_round_tls_turn_t *turns,
    size_t turn_capacity,vireo_task_t **owner,vireo_async_round_tls_report_t *out) {
    int const saved=errno; vireo_async_round_tls_report_t value={0};
    if(!server || !store || !pool || !configure || !ready || !turns || !owner || !out || *owner ||
        close_bytes==0 || turn_capacity==0)
        return finish(VIREO_RESULT_INVALID_ARGUMENT,value,out,saved);
    if(ready_count>VIREO_TCP_SERVER_MAX_CONNECTIONS || turn_capacity>VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        ready_count>turn_capacity) return finish(VIREO_RESULT_RANGE,value,out,saved);
    value.stage=VIREO_ASYNC_ROUND_TLS_VALIDATE;
    vireo_tcp_server_tls_info_t root={0};
    vireo_result_t const result=vireo_tcp_server_tls_inspect(server,&root,&value.validation_error);
    if(result!=VIREO_OK) return finish(result,value,out,saved);
    if(close_bytes<minimum(root.options.io.read_capacity,VIREO_TLS_IO_SCRATCH_BYTES) ||
        close_bytes<minimum(root.options.io.write_capacity,VIREO_TLS_IO_SCRATCH_BYTES))
        return finish(VIREO_RESULT_RANGE,value,out,saved);
    value.effective_max_clients=ready_count;
    return process_ready(server,store,pool,close_bytes,configure,context,ready,ready_count,turns,owner,
        value,out,&default_ops,NULL,saved);
}
