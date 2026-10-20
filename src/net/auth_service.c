/* PROJECT : VIREO
 * FILE : auth_service.c
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : 只经公开边界组合认证服务；跨轮保留不可逆前缀和唯一owner。 */
#define _POSIX_C_SOURCE 200809L
#include <vireo/net/auth_service.h>
#include "auth_request_rejection_internal.h"
#include <vireo/base/checked.h>
#include <vireo/thread/completion_queue.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

#define MEMORY_MAX ((size_t)67108864)
typedef struct client_slot {
    vireo_connection_pool_lease_t client; /* 非空即本服务尚未归还的精确代次。 */
    vireo_auth_request_head_receipt_t head; /* 唯一请求防重门禁，无密码副本。 */
    vireo_auth_request_rejection_receipt_t rejection; /* 已消费拒绝的enqueue/refresh进度。 */
    vireo_task_t *task; /* 原提交失败的未移交owner，不能当作新请求重投。 */
    bool audit_decided; /* 与head同寿命，消费/发送恢复不得重投。 */
    bool closing; /* 一旦设置不再收新帧/提交，清理完成才release。 */
    size_t cleanup_index; /* 同一client的inflight有界扫描恢复点。 */
} client_slot_t;
struct vireo_auth_service {
    vireo_auth_service_resources_t r; /* 借用至destroy，worker不接这些网络对象。 */
    vireo_auth_service_options_t o; /* 固定显式数值。 */
    vireo_event_loop_handle_t handle; /* 拥有注销义务，不拥有notifier fd。 */
    size_t capacity, active, sweep, ready_count, ready_next; /* 槽容量/持有数/公平清理扫描/selected前缀。 */
    bool quiescing; /* 永久拒绝新accept/task，不停止旧结果发送。 */
    client_slot_t *slots;
    vireo_tcp_server_ready_client_t *ready;
    vireo_connection_pool_lease_t *accepted;
    vireo_completion_t *completion; /* 唯一原结果，满FIFO或刷新错时保留。 */
    vireo_auth_response_consumer_receipt_t receipt;
};
static bool same(vireo_connection_pool_lease_t a,vireo_connection_pool_lease_t b)
{ return a.pool_id==b.pool_id && a.slot_index==b.slot_index && a.generation==b.generation; }
static vireo_connection_pool_lease_t client_of(vireo_task_metadata_t m)
{ return (vireo_connection_pool_lease_t){m.route.client_owner_id,m.route.client_slot_index,m.route.client_generation}; }
static size_t min_size(size_t a,size_t b) { return a<b?a:b; }
static vireo_result_t done(vireo_result_t rc,int saved) { errno=saved; return rc; }
/** 只找本服务持有的完整租约，不用slot_index单独认证身份。 */
static client_slot_t *find(vireo_auth_service_t *s,vireo_connection_pool_lease_t c)
{ return c.pool_id && c.slot_index<s->capacity && same(s->slots[c.slot_index].client,c)?&s->slots[c.slot_index]:NULL; }
static void client_error(vireo_auth_service_report_t *p,client_slot_t *slot,vireo_result_t rc)
{
    slot->closing=true;
    if(p->first_client_result==VIREO_OK) { p->first_client_result=rc; p->first_failed_client=slot->client; }
}
/** 可信UTC只作Session响应过期判断；原errno由最外入口恢复。 */
static vireo_result_t utc_now(uint64_t *out)
{
    struct timespec t;
    if(clock_gettime(CLOCK_REALTIME,&t)!=0) return VIREO_RESULT_IO;
    if(t.tv_sec<0 || t.tv_nsec<0 || t.tv_nsec>=1000000000L) return VIREO_RESULT_INTERNAL;
    if((uintmax_t)t.tv_sec>UINT64_MAX/1000) return VIREO_RESULT_OVERFLOW;
    return vireo_checked_u64_add((uint64_t)t.tv_sec*1000,(uint64_t)t.tv_nsec/1000000,out);
}
/** 放弃结果只结束原owner/候选；已入FIFO/绑定不可回滚，随后整客户清理。 */
static vireo_result_t discard(vireo_auth_service_t *s)
{
    return vireo_auth_response_consumer_abandon(s->r.sessions,&s->completion,&s->receipt);
}
/** 每客户有限清理，任一失败保原owner/游标，release后才清槽。 */
static vireo_result_t cleanup(vireo_auth_service_t *s,client_slot_t *slot,vireo_auth_service_report_t *p)
{
    vireo_result_t rc;
    if(s->completion && same(client_of(s->receipt.metadata.request),slot->client)) {
        rc=discard(s); if(rc!=VIREO_OK) return rc;
    }
    rc=vireo_task_destroy(&slot->task); if(rc!=VIREO_OK) return rc;
    vireo_inflight_client_cleanup_report_t clean;
    rc=vireo_inflight_store_cancel_client_batch(s->r.store,slot->client,slot->cleanup_index,s->o.cleanup_slots,&clean);
    slot->cleanup_index=clean.next_index;
    if(rc!=VIREO_OK || clean.stop_reason!=VIREO_INFLIGHT_CLIENT_CLEANUP_COMPLETE) return rc;
    rc=vireo_auth_session_forget(s->r.sessions,slot->client);
    if(rc!=VIREO_OK && rc!=VIREO_RESULT_NOT_FOUND) return rc;
    rc=vireo_tcp_server_release_client(s->r.server,&slot->client,NULL);
    if(rc!=VIREO_OK) return rc;
    *slot=(client_slot_t){0}; --s->active; ++p->released; return VIREO_OK;
}
/** 一个已消费head的后续义务；拒绝满FIFO保门禁，移交成功绝不生成第二响应。 */
static vireo_result_t finish_head(vireo_auth_service_t *s,client_slot_t *slot,vireo_auth_service_report_t *p)
{
    vireo_result_t rc;
    if(slot->head.state==VIREO_AUTH_REQUEST_HEAD_NEEDS_CONSUME) {
        rc=vireo_auth_request_head_resume_consume(s->r.server,&slot->head,&p->head);
        if(rc!=VIREO_OK) return rc;
    }
    if(slot->head.state==VIREO_AUTH_REQUEST_HEAD_EMPTY) return VIREO_OK;
    rc=vireo_task_destroy(&slot->task); if(rc!=VIREO_OK) return rc;
    vireo_async_request_report_t const *submitted=&slot->head.submit_report.submit_report;
    if(!submitted->task_transferred && submitted->submit_report.record_retained) return VIREO_RESULT_INTERNAL;
    if(submitted->task_transferred) {
        rc=vireo_auth_request_head_acknowledge(&slot->head);
        if(rc==VIREO_OK) slot->audit_decided=false;
        return rc;
    }
    rc=vireo_auth_request_rejection_step(s->r.server,&slot->head,&slot->rejection,&p->rejection);
    if(rc==VIREO_RESULT_RANGE && p->rejection.stage==VIREO_AUTH_REQUEST_REJECTION_ENQUEUE) {
        p->response_blocked=true; return VIREO_OK;
    }
    if(rc!=VIREO_OK) return rc;
    ++p->rejected;
    rc=vireo_auth_request_rejection_acknowledge(&slot->head,&slot->rejection);
    if(rc==VIREO_OK) slot->audit_decided=false;
    return rc;
}
/** 短借TLS至本客户turn结束；稳定WRITE retry优先，收发预算不重复领取。 */
static vireo_result_t application(vireo_auth_service_t *s,client_slot_t *slot,
    vireo_tls_connection_t *tls,vireo_auth_service_report_t *p)
{
    vireo_tls_io_info_t io;
    vireo_result_t rc=vireo_tls_connection_io_inspect(tls,&io,NULL); if(rc!=VIREO_OK) return rc;
    if(io.state!=VIREO_TLS_IO_OPEN) return VIREO_RESULT_PROTOCOL;
    vireo_tcp_server_tls_flow_info_t sync;
    rc=vireo_tcp_server_client_tls_flow_refresh(s->r.server,slot->client,&sync,NULL); if(rc!=VIREO_OK) return rc;
    vireo_tls_io_flow_t flow=sync.flow;
    vireo_tls_io_progress_t progress;
    bool sent=false;
    if(flow.priority_retry==VIREO_TLS_IO_OPERATION_WRITE) {
        rc=vireo_tls_connection_send(tls,&s->o.send,&progress,NULL); sent=true;
        if(rc!=VIREO_OK) return rc;
        rc=vireo_tls_connection_flow_refresh(tls,&flow,NULL); if(rc!=VIREO_OK) return rc;
    }
    /* 原首帧尚未消费时禁止receive改写其源；仍允许发送以腾写区。 */
    if(slot->head.state!=VIREO_AUTH_REQUEST_HEAD_NEEDS_CONSUME &&
       (flow.application_read_enabled || flow.priority_retry==VIREO_TLS_IO_OPERATION_READ)) {
        rc=vireo_tls_connection_receive(tls,&s->o.receive,&progress,NULL); if(rc!=VIREO_OK) return rc;
    }
    if(slot->head.state!=VIREO_AUTH_REQUEST_HEAD_EMPTY) {
        rc=finish_head(s,slot,p); if(rc!=VIREO_OK) return rc;
    } else if(!s->quiescing) {
        vireo_connection_frame_view_t view;
        vireo_connection_frame_options_t const fo={VIREO_CONNECTION_FRAME_REQUEST,VIREO_AUTH_REQUEST_FRAME_MAX};
        vireo_connection_frame_budget_t const fb={1,VIREO_AUTH_REQUEST_FRAME_MAX};
        vireo_connection_frame_info_t frames;
        rc=vireo_tcp_server_client_frames_peek(s->r.server,slot->client,&fo,&fb,&view,1,&frames,NULL);
        if(rc!=VIREO_OK) return rc;
        if(frames.frame_count) {
            if(view.header.command!=VIREO_COMMAND_REGISTER && view.header.command!=VIREO_COMMAND_LOGIN &&
               view.header.command!=VIREO_COMMAND_LOGOUT && view.header.command!=VIREO_COMMAND_SESSION_RESUME)
                return VIREO_RESULT_PROTOCOL;
            uint64_t now=0,deadline=0;
            rc=vireo_clock_monotonic_now(&now,NULL); if(rc!=VIREO_OK) return rc;
            rc=vireo_checked_u64_add(now,s->o.request_timeout_ns,&deadline); if(rc!=VIREO_OK) return rc;
            vireo_auth_request_submit_options_t const o={s->o.task_allocation_budget,s->o.max_client_requests,
                s->o.register_operation,s->o.login_operation,deadline,s->o.logout_operation,s->o.resume_operation};
            uint64_t utc=0; rc=utc_now(&utc); if(rc!=VIREO_OK) return rc;
            /* view至此结束借用，head重新peek并在消费前保存防重凭据。 */
            rc=vireo_auth_request_submit_read_head(s->r.server,slot->client,s->r.store,s->r.workers,
                s->r.admission,now,s->r.sessions,utc,&o,NULL,&slot->head,&slot->task,&p->head);
            if(slot->head.state!=VIREO_AUTH_REQUEST_HEAD_EMPTY && !slot->audit_decided) {
                slot->audit_decided=true;
                vireo_status_t status=0;
                if(s->r.audit && vireo_auth_request_rejection_classify(&slot->head,&status)==VIREO_OK) {
                    uint16_t action=slot->head.command==VIREO_COMMAND_REGISTER?1:
                        slot->head.command==VIREO_COMMAND_LOGIN?2:
                        slot->head.command==VIREO_COMMAND_LOGOUT?3:4;
                    vireo_auth_failure_event_t const event={.occurred_at_ms=utc,.action=action,
                        .status=(uint16_t)status,.origin=VIREO_AUTH_FAILURE_REACTOR};
                    vireo_auth_failure_disposition_t disposition;
                    (void)vireo_auth_failure_audit_try_offer(s->r.audit,&event,now,&disposition);
                }
            }
            if(p->head.receipt.submit_report.submit_report.task_transferred) ++p->submitted;
            if(slot->head.state==VIREO_AUTH_REQUEST_HEAD_EMPTY) { if(rc!=VIREO_OK) return rc; }
            else { rc=finish_head(s,slot,p); if(rc!=VIREO_OK) return rc; }
        }
    }
    rc=vireo_tls_connection_flow_refresh(tls,&flow,NULL); if(rc!=VIREO_OK) return rc;
    if(!sent && flow.priority_retry!=VIREO_TLS_IO_OPERATION_READ &&
       (flow.want_write || flow.priority_retry==VIREO_TLS_IO_OPERATION_WRITE)) {
        rc=vireo_tls_connection_send(tls,&s->o.send,&progress,NULL); if(rc!=VIREO_OK) return rc;
    }
    rc=vireo_tcp_server_client_tls_flow_refresh(s->r.server,slot->client,&sync,NULL); if(rc!=VIREO_OK) return rc;
    rc=vireo_tls_connection_io_inspect(tls,&io,NULL); if(rc!=VIREO_OK) return rc;
    if(slot->head.state!=VIREO_AUTH_REQUEST_HEAD_EMPTY &&
       io.write_size<=io.options.write_capacity-32)
        return vireo_tcp_server_schedule_client(s->r.server,slot->client,NULL);
    /* 仅完整帧安排业务续处理；半帧绝不因read_size非零忙排队。 */
    if(!s->quiescing && slot->head.state==VIREO_AUTH_REQUEST_HEAD_EMPTY && io.read_size) {
        vireo_connection_frame_view_t next;
        vireo_connection_frame_options_t const fo={VIREO_CONNECTION_FRAME_REQUEST,VIREO_AUTH_REQUEST_FRAME_MAX};
        vireo_connection_frame_budget_t const fb={1,VIREO_AUTH_REQUEST_FRAME_MAX};
        vireo_connection_frame_info_t frames;
        rc=vireo_tcp_server_client_frames_peek(s->r.server,slot->client,&fo,&fb,&next,1,&frames,NULL);
        if(rc!=VIREO_OK) return rc;
        if(frames.frame_count) return vireo_tcp_server_schedule_client(s->r.server,slot->client,NULL);
    }
    if(io.read_eof && !io.read_size && !io.write_size && slot->head.state==VIREO_AUTH_REQUEST_HEAD_EMPTY) {
        size_t count=0;
        rc=vireo_inflight_store_count_client(s->r.store,slot->client,&count,NULL); if(rc!=VIREO_OK) return rc;
        bool const pending=s->completion && same(client_of(s->receipt.metadata.request),slot->client);
        if(!count && !pending) slot->closing=true;
    }
    return VIREO_OK;
}
/** 每次ready只做握手或应用，不从握手同轮跳进认证。 */
static vireo_result_t turn(vireo_auth_service_t *s,client_slot_t *slot,vireo_auth_service_report_t *p)
{
    if(slot->closing) return VIREO_OK;
    vireo_tls_connection_t *tls=NULL;
    vireo_result_t rc=vireo_tcp_server_client_tls_borrow(s->r.server,slot->client,&tls,NULL);
    if(rc!=VIREO_OK) return rc;
    vireo_tls_connection_info_t connection;
    rc=vireo_tls_connection_inspect(tls,&connection,NULL); if(rc!=VIREO_OK) return rc;
    if(connection.handshake_state!=VIREO_TLS_HANDSHAKE_ESTABLISHED) {
        vireo_tcp_server_tls_handshake_info_t h;
        rc=vireo_tcp_server_client_tls_handshake_step(s->r.server,slot->client,&h,&p->tls_error);
        if(rc==VIREO_OK && h.application_ready) rc=vireo_tcp_server_schedule_client(s->r.server,slot->client,NULL);
        return rc;
    }
    return application(s,slot,tls,p);
}
/** 一次提示读取和独立预算领取，提示计数不决定领取量；满响应只保原owner。 */
static vireo_result_t completions(vireo_auth_service_t *s,vireo_auth_service_report_t *p)
{
    uint64_t hints=0;
    vireo_result_t rc=vireo_notifier_consume(s->r.notifier,&hints,NULL); if(rc!=VIREO_OK) return rc;
    for(size_t i=0;i<s->o.max_completions;++i) {
        if(!s->completion) {
            vireo_completion_queue_transfer_report_t transfer;
            rc=vireo_completion_queue_try_pop(s->r.queue,&s->completion,&transfer);
            if(rc==VIREO_RESULT_NOT_FOUND || rc==VIREO_RESULT_CANCELLED || rc==VIREO_RESULT_BUSY) {
                if(!transfer.transferred) return VIREO_OK;
            }
            if(rc!=VIREO_OK) return rc;
        }
        vireo_completion_info_t info;
        rc=vireo_completion_inspect(s->completion,&info); if(rc!=VIREO_OK) return rc;
        client_slot_t *slot=find(s,client_of(info.metadata.request));
        if(slot && p->stopped) slot->closing=true;
        if(slot && slot->closing) { rc=discard(s); if(rc!=VIREO_OK) return rc; }
        else {
            uint64_t now=0; rc=utc_now(&now); if(rc!=VIREO_OK) return rc;
            vireo_auth_response_consumer_options_t const o={s->o.register_operation,s->o.login_operation,s->o.logout_operation,s->o.resume_operation};
            rc=vireo_auth_response_consumer_step(s->r.server,s->r.store,s->r.sessions,&s->completion,
                &o,now,&s->receipt,&p->consumer);
            if(rc==VIREO_RESULT_RANGE && p->consumer.stage==VIREO_AUTH_CONSUMER_ENQUEUE) {
                p->response_blocked=true;
                return slot?VIREO_OK:VIREO_RESULT_INTERNAL;
            }
            if(rc!=VIREO_OK) {
                /* take前异常同样保原结果，caller可修复基础设施或disconnect此客户。 */
                return rc;
            }
            if(s->receipt.state==VIREO_AUTH_CONSUMER_READY) {
                rc=vireo_auth_response_consumer_acknowledge(s->completion,&s->receipt); if(rc!=VIREO_OK) return rc;
            }
            /* EOF无新READ时，完成入队也必须安排一次发送/终态检查。 */
            if(slot) { rc=vireo_tcp_server_schedule_client(s->r.server,slot->client,NULL); if(rc!=VIREO_OK) return rc; }
        }
        ++p->completions;
    }
    vireo_notifier_notify_outcome_t notified;
    return vireo_notifier_notify(s->r.notifier,&notified,NULL);
}

vireo_result_t vireo_auth_service_create(vireo_auth_service_resources_t const *resources,
    vireo_auth_service_options_t const *options,vireo_auth_service_t **owner)
{
    int const saved=errno;
    if(!resources || !options || !owner || *owner) return done(VIREO_RESULT_INVALID_ARGUMENT,saved);
    vireo_auth_service_resources_t const r=*resources;
    vireo_auth_service_options_t const o=*options;
    if(!r.server || !r.store || !r.workers || !r.admission || !r.sessions || !r.queue || !r.notifier ||
       !o.max_clients || !o.admit.max_accepts || !o.admit.max_accept_syscalls || !o.max_completions ||
       !o.cleanup_slots || !o.receive.max_bytes || !o.receive.max_native_calls || !o.send.max_bytes ||
       !o.send.max_native_calls || !o.task_allocation_budget || !o.max_client_requests ||
       !o.register_operation || !o.login_operation || !o.logout_operation || !o.resume_operation ||
       o.register_operation==o.login_operation || o.register_operation==o.logout_operation ||
       o.register_operation==o.resume_operation || o.login_operation==o.logout_operation ||
       o.login_operation==o.resume_operation || o.logout_operation==o.resume_operation ||
       !o.request_timeout_ns || !o.max_memory_bytes) return done(VIREO_RESULT_INVALID_ARGUMENT,saved);
    vireo_tcp_server_info_t root; vireo_tcp_server_tls_info_t tls;
    vireo_inflight_store_info_t inflight; vireo_thread_pool_info_t workers; vireo_completion_queue_info_t queue;
    vireo_result_t rc=vireo_tcp_server_inspect(r.server,&root); if(rc!=VIREO_OK) return done(rc,saved);
    rc=vireo_tcp_server_tls_inspect(r.server,&tls,NULL); if(rc!=VIREO_OK) return done(rc,saved);
    rc=vireo_inflight_store_inspect(r.store,&inflight); if(rc!=VIREO_OK) return done(rc,saved);
    rc=vireo_thread_pool_inspect(r.workers,&workers); if(rc!=VIREO_OK) return done(rc,saved);
    rc=vireo_completion_queue_inspect(r.queue,&queue); if(rc!=VIREO_OK) return done(rc,saved);
    if(root.stop_requested || workers.stop_requested || queue.closed) return done(VIREO_RESULT_CANCELLED,saved);
    if(!root.listener_owned || !root.listener_bound || !queue.wait_prepared) return done(VIREO_RESULT_NOT_FOUND,saved);
    if(root.connection_count || inflight.count || !workers.execution_enabled || !workers.configured ||
       root.processing_active || root.driving_active || root.scheduling_active || root.serving_active ||
       root.shutdown_active || root.closing_active) return done(VIREO_RESULT_BUSY,saved);
    if(o.max_clients>root.connection_capacity || o.admit.max_accepts>root.connection_capacity ||
       o.max_completions>65536 || o.cleanup_slots>65536 || o.max_client_requests>inflight.capacity ||
       o.task_allocation_budget>MEMORY_MAX || o.max_memory_bytes>MEMORY_MAX ||
       tls.options.io.read_capacity<VIREO_AUTH_REQUEST_FRAME_MAX ||
       tls.options.io.max_read_unit_bytes<VIREO_AUTH_REQUEST_FRAME_MAX || tls.options.io.write_capacity<104 ||
       o.receive.max_bytes<min_size(tls.options.io.read_capacity,VIREO_TLS_IO_SCRATCH_BYTES) ||
       o.send.max_bytes<min_size(tls.options.io.write_capacity,VIREO_TLS_IO_SCRATCH_BYTES)) return done(VIREO_RESULT_RANGE,saved);
    size_t slots_bytes=0,ready_bytes=0,accepted_bytes=0,total=sizeof(vireo_auth_service_t);
    rc=vireo_checked_size_mul(root.connection_capacity,sizeof(client_slot_t),&slots_bytes);
    if(rc==VIREO_OK) rc=vireo_checked_size_mul(o.max_clients,sizeof(vireo_tcp_server_ready_client_t),&ready_bytes);
    if(rc==VIREO_OK) rc=vireo_checked_size_mul(o.admit.max_accepts,sizeof(vireo_connection_pool_lease_t),&accepted_bytes);
    if(rc==VIREO_OK) rc=vireo_checked_size_add(total,slots_bytes,&total);
    if(rc==VIREO_OK) rc=vireo_checked_size_add(total,ready_bytes,&total);
    if(rc==VIREO_OK) rc=vireo_checked_size_add(total,accepted_bytes,&total);
    if(rc!=VIREO_OK) return done(rc,saved);
    if(total>o.max_memory_bytes) return done(VIREO_RESULT_RANGE,saved);
    /* 各数组需本类型对齐；分开calloc避免控制块尾部不同类型对齐假设。 */
    vireo_auth_service_t *s=calloc(1,sizeof(*s)); if(!s) return done(VIREO_RESULT_NO_MEMORY,saved);
    s->slots=calloc(root.connection_capacity,sizeof(*s->slots));
    s->ready=calloc(o.max_clients,sizeof(*s->ready)); s->accepted=calloc(o.admit.max_accepts,sizeof(*s->accepted));
    if(!s->slots || !s->ready || !s->accepted) { rc=VIREO_RESULT_NO_MEMORY; goto fail; }
    s->r=r; s->o=o; s->capacity=root.connection_capacity;
    rc=vireo_notifier_server_register(r.server,r.notifier,&s->handle,NULL); if(rc!=VIREO_OK) goto fail;
    *owner=s; return done(VIREO_OK,saved);
fail:
    free(s->accepted); free(s->ready); free(s->slots); free(s); return done(rc,saved);
}

vireo_result_t vireo_auth_service_once(vireo_auth_service_t *s,int timeout,vireo_auth_service_report_t *out)
{
    int const saved=errno; vireo_auth_service_report_t p={0}; vireo_result_t rc=VIREO_OK;
    if(!s || !out || timeout<0) { rc=VIREO_RESULT_INVALID_ARGUMENT; goto finish; }
    if(timeout>1000) { rc=VIREO_RESULT_RANGE; goto finish; }
    vireo_tcp_server_info_t root;
    rc=vireo_tcp_server_inspect(s->r.server,&root); if(rc!=VIREO_OK) goto finish;
    if(root.processing_active || root.driving_active || root.scheduling_active || root.serving_active ||
       root.shutdown_active || root.closing_active) { rc=VIREO_RESULT_BUSY; goto finish; }
    p.stopped=root.stop_requested; if(p.stopped) s->quiescing=true;
    /* 清理游标按槽公平轮转；空槽同样消耗扫描预算。 */
    for(size_t i=0;i<s->o.max_clients;++i) {
        client_slot_t *slot=&s->slots[s->sweep]; s->sweep=(s->sweep+1)%s->capacity;
        if(!slot->client.pool_id) continue;
        if(p.stopped) slot->closing=true;
        if(slot->closing) { rc=cleanup(s,slot,&p); if(rc!=VIREO_OK) goto finish; }
    }
    rc=completions(s,&p); if(rc!=VIREO_OK) goto finish;
    if(p.stopped) { s->ready_count=0; s->ready_next=0; goto finish; }
    vireo_tcp_server_tls_admission_info_t pressure;
    if(s->quiescing) rc=vireo_tcp_server_set_listener_read_enabled(s->r.server,false,NULL);
    else rc=vireo_tcp_server_tls_admission_refresh(s->r.server,&pressure,NULL);
    if(rc!=VIREO_OK) goto finish;
    if(s->ready_next==s->ready_count) {
        s->ready_count=0; s->ready_next=0; p.poll_called=true;
        int const wait=(p.completions || p.released)?0:timeout;
        rc=vireo_tcp_server_tls_poll_ready_once(s->r.server,wait,s->o.max_clients,s->ready,s->o.max_clients,&p.poll,&p.tls_error);
        s->ready_count=p.poll.poll.selected_count;
        if(rc!=VIREO_OK) goto post;
        if(p.poll.poll.stopped) { s->quiescing=true; p.stopped=true; goto post; }
        uint32_t events=p.poll.listener_events;
        if(events&(VIREO_EPOLL_EVENT_ERROR|VIREO_EPOLL_EVENT_HANGUP)) { rc=VIREO_RESULT_IO; goto post; }
        vireo_tcp_server_auxiliary_event_t event;
        rc=vireo_tcp_server_auxiliary_read_take_ready(s->r.server,&event,NULL);
        if(rc==VIREO_OK) {
            if(event.handle.loop_id!=s->handle.loop_id || event.handle.token!=s->handle.token) { rc=VIREO_RESULT_NOT_FOUND; goto post; }
            if(event.events!=VIREO_EPOLL_EVENT_READ) { rc=VIREO_RESULT_IO; goto post; }
        } else if(rc!=VIREO_RESULT_NOT_FOUND) goto post;
        rc=VIREO_OK;
    }
    while(s->ready_next<s->ready_count) {
        vireo_connection_pool_lease_t const c=s->ready[s->ready_next++].client;
        client_slot_t *slot=find(s,c); if(!slot) continue; ++p.client_turns;
        vireo_result_t const local=turn(s,slot,&p);
        if(local!=VIREO_OK) client_error(&p,slot,local);
    }
    if(!s->quiescing && (p.poll.listener_events&VIREO_EPOLL_EVENT_READ)) {
        for(size_t i=0;i<s->o.admit.max_accepts;++i) s->accepted[i]=(vireo_connection_pool_lease_t){0};
        vireo_tcp_server_tls_admit_info_t admitted;
        rc=vireo_tcp_server_tls_admit_batch(s->r.server,&s->o.admit,s->accepted,s->o.admit.max_accepts,&admitted,&p.tls_error);
        p.admitted=admitted.admission.admitted_count;
        for(size_t i=0;i<p.admitted;++i) {
            vireo_connection_pool_lease_t c=s->accepted[i];
            if(c.slot_index>=s->capacity || s->slots[c.slot_index].client.pool_id) { rc=VIREO_RESULT_INTERNAL; break; }
            s->slots[c.slot_index].client=c; ++s->active;
        }
    }
post:
    if(s->quiescing) p.post_pressure_result=vireo_tcp_server_set_listener_read_enabled(s->r.server,false,NULL);
    else p.post_pressure_result=vireo_tcp_server_tls_admission_refresh(s->r.server,&pressure,NULL);
    if(rc==VIREO_OK) rc=p.post_pressure_result;
finish:
    if(s) p.quiescing=s->quiescing;
    if(out) *out=p;
    return done(rc,saved);
}
vireo_result_t vireo_auth_service_quiesce(vireo_auth_service_t *s)
{ if(!s) return VIREO_RESULT_INVALID_ARGUMENT; s->quiescing=true; return VIREO_OK; }
vireo_result_t vireo_auth_service_disconnect(vireo_auth_service_t *s,vireo_connection_pool_lease_t c)
{
    if(!s) return VIREO_RESULT_INVALID_ARGUMENT;
    client_slot_t *slot=find(s,c); if(!slot) return VIREO_RESULT_NOT_FOUND;
    slot->closing=true; return VIREO_OK;
}
vireo_result_t vireo_auth_service_destroy(vireo_auth_service_t **owner)
{
    int const saved=errno;
    if(!owner) return done(VIREO_RESULT_INVALID_ARGUMENT,saved);
    vireo_auth_service_t *s=*owner; if(!s) return done(VIREO_OK,saved);
    if(s->active || s->completion || s->receipt.state || s->ready_next<s->ready_count) return done(VIREO_RESULT_BUSY,saved);
    vireo_result_t rc=vireo_notifier_server_unregister(s->r.server,&s->handle,NULL); if(rc!=VIREO_OK) return done(rc,saved);
    free(s->accepted); free(s->ready); free(s->slots); free(s); *owner=NULL;
    return done(VIREO_OK,saved);
}
