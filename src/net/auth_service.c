/* PROJECT : VIREO
 * FILE : auth_service.c
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : 只经公开边界组合认证服务；跨轮保留不可逆前缀和唯一owner。 */
#define _POSIX_C_SOURCE 200809L
#include "directory_mkdir_reactor_internal.h"
#include <vireo/base/secure_clear.h>
#include "auth_request_rejection_internal.h"
#include <vireo/base/checked.h>
#include <vireo/thread/completion_queue.h>
#include <vireo/net/timer_loop.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

#define MEMORY_MAX ((size_t)67108864)
static bool same(vireo_connection_pool_lease_t a,vireo_connection_pool_lease_t b)
{ return a.pool_id==b.pool_id && a.slot_index==b.slot_index && a.generation==b.generation; }
static vireo_connection_pool_lease_t client_of(vireo_task_metadata_t m)
{ return (vireo_connection_pool_lease_t){m.route.client_owner_id,m.route.client_slot_index,m.route.client_generation}; }
static size_t min_size(size_t a,size_t b) { return a<b?a:b; }
static vireo_result_t done(vireo_result_t rc,int saved) { errno=saved; return rc; }
/** 只找本服务持有的完整租约，不用slot_index单独认证身份。 */
static client_slot_t *find(vireo_auth_service_t *s,vireo_connection_pool_lease_t c)
{ return c.pool_id && c.slot_index<s->capacity && same(s->slots[c.slot_index].client,c)?&s->slots[c.slot_index]:NULL; }
static void client_error(vireo_auth_service_t *s,vireo_auth_service_report_t *p,client_slot_t *slot,vireo_result_t rc)
{
    vireo_auth_service_close_slot(s,slot);
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
    vireo_completion_info_t info;
    vireo_result_t rc=vireo_completion_inspect(s->completion,&info); if(rc!=VIREO_OK) return rc;
    rc=vireo_auth_response_consumer_abandon(s->r.sessions,&s->completion,&s->receipt);
    if(!s->completion && s->stat_queue) vireo_stat_reactor_forget(s,info.metadata.request);
    return rc;
}
/** 每客户有限清理，任一失败保原owner/游标，release后才清槽。 */
static vireo_result_t cleanup(vireo_auth_service_t *s,client_slot_t *slot,vireo_auth_service_report_t *p)
{
    vireo_result_t rc=vireo_auth_deadline_cancel(s,slot); if(rc!=VIREO_OK) return rc;
    if(s->completion) {
        vireo_completion_info_t info;
        rc=vireo_completion_inspect(s->completion,&info); if(rc!=VIREO_OK) return rc;
        if(same(client_of(info.metadata.request),slot->client)) { rc=discard(s); if(rc!=VIREO_OK) return rc; }
    }
    if(s->stat_completion) {
        vireo_completion_info_t info;
        rc=vireo_completion_inspect(s->stat_completion,&info); if(rc!=VIREO_OK) return rc;
        if(same(client_of(info.metadata.request),slot->client)) { rc=vireo_stat_reactor_discard(s); if(rc!=VIREO_OK) return rc; }
    }
    if(s->root_completion) {
        vireo_completion_info_t info;
        rc=vireo_completion_inspect(s->root_completion,&info); if(rc!=VIREO_OK) return rc;
        if(same(client_of(info.metadata.request),slot->client)) { rc=vireo_root_reactor_discard(s); if(rc!=VIREO_OK) return rc; }
    }
    if(s->list && s->list->completion) {
        vireo_completion_info_t info;
        rc=vireo_completion_inspect(s->list->completion,&info); if(rc!=VIREO_OK) return rc;
        if(same(client_of(info.metadata.request),slot->client)) { rc=vireo_list_reactor_discard(s); if(rc!=VIREO_OK) return rc; }
    }
    if(s->mkdir && s->mkdir->completion) {
        vireo_completion_info_t info;
        rc=vireo_completion_inspect(s->mkdir->completion,&info); if(rc!=VIREO_OK) return rc;
        if(same(client_of(info.metadata.request),slot->client)) {
            size_t const before=s->mkdir->report.completions;
            rc=vireo_mkdir_reactor_discard(s); p->completions+=s->mkdir->report.completions-before; if(rc!=VIREO_OK) return rc;
        }
    }
    rc=vireo_task_destroy(&slot->task); if(rc!=VIREO_OK) return rc;
    if(!slot->records_cleaned) {
        vireo_inflight_client_cleanup_report_t clean;
        rc=vireo_inflight_store_cancel_client_batch(s->r.store,slot->client,slot->cleanup_index,s->o.cleanup_slots,&clean);
        slot->cleanup_index=clean.next_index;
        if(rc!=VIREO_OK || clean.stop_reason!=VIREO_INFLIGHT_CLIENT_CLEANUP_COMPLETE) return rc;
        slot->records_cleaned=true;
    }
    size_t scanned=0;
    while(slot->expected_cursor<s->expected_capacity && scanned++<s->o.cleanup_slots) {
        vireo_stat_expected_t *e=&s->expected[slot->expected_cursor++];
        if(e->command && same(client_of(e->metadata),slot->client)) {
            if(e->committed) --s->expected_count;
            vireo_list_reactor_clear_request(s,(size_t)(e-s->expected));
            vireo_mkdir_reactor_clear_request(s,(size_t)(e-s->expected));
            *e=(vireo_stat_expected_t){0};
        }
    }
    if(slot->expected_cursor<s->expected_capacity) return VIREO_OK;
    rc=vireo_auth_session_forget(s->r.sessions,slot->client);
    if(rc!=VIREO_OK && rc!=VIREO_RESULT_NOT_FOUND) return rc;
    if(s->mkdir) (void)vireo_secure_clear(&s->mkdir->heads[slot->client.slot_index],sizeof(*s->mkdir->heads));
    if(s->list) (void)vireo_secure_clear(&s->list->heads[slot->client.slot_index],sizeof(*s->list->heads));
    rc=vireo_tcp_server_release_client(s->r.server,&slot->client,NULL);
    if(rc!=VIREO_OK) return rc;
    *slot=(client_slot_t){0}; --s->active; --s->closing_count; ++p->released; return VIREO_OK;
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
/** 即使未启deadline，也先按完整header拒绝非MKDIR超旧156上界。 */
static vireo_result_t peek_frame(vireo_auth_service_t *s,client_slot_t *slot,
    vireo_connection_frame_view_t *view,vireo_connection_frame_info_t *frames)
{
    unsigned char const *wire=NULL; size_t size=0;
    vireo_result_t rc=vireo_tcp_server_client_read_peek(s->r.server,slot->client,&wire,&size,NULL);
    if(rc!=VIREO_OK) return rc;
    if(size>=VIREO_PROTOCOL_HEADER_SIZE) {
        vireo_protocol_header_t header; vireo_protocol_codec_issue_t issue;
        rc=vireo_protocol_header_decode(wire,size,&header,&issue);
        if(rc==VIREO_OK) rc=vireo_protocol_request_header_validate(&header,&issue);
        if(rc!=VIREO_OK) return rc;
        if(header.body_len>vireo_auth_command_frame_max(s,header.command)-VIREO_PROTOCOL_HEADER_SIZE) return VIREO_RESULT_PROTOCOL;
    }
    size_t const maximum=vireo_auth_frame_max(s);
    vireo_connection_frame_options_t const options={VIREO_CONNECTION_FRAME_REQUEST,maximum};
    vireo_connection_frame_budget_t const budget={1,maximum};
    return vireo_tcp_server_client_frames_peek(s->r.server,slot->client,&options,&budget,view,1,frames,NULL);
}
/** 短借TLS至本客户turn结束；稳定WRITE retry优先，收发预算不重复领取。 */
static vireo_result_t application(vireo_auth_service_t *s,client_slot_t *slot,
    vireo_tls_connection_t *tls,vireo_auth_service_report_t *p)
{
    size_t const submitted_before=p->submitted;
    vireo_list_head_t *lh=s->list?&s->list->heads[slot->client.slot_index]:NULL;
    vireo_mkdir_head_t *mh=s->mkdir?&s->mkdir->heads[slot->client.slot_index]:NULL;
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
    if(slot->head.state!=VIREO_AUTH_REQUEST_HEAD_NEEDS_CONSUME && slot->stat_head.state!=1 && slot->root_head.state!=1 && (!lh || lh->state!=1) && (!mh || mh->state!=1) &&
       (flow.application_read_enabled || flow.priority_retry==VIREO_TLS_IO_OPERATION_READ)) {
        rc=vireo_tls_connection_receive(tls,&s->o.receive,&progress,NULL); if(rc!=VIREO_OK) return rc;
    }
    rc=vireo_auth_deadline_frames(s,slot,io.read_size,p);
    if(rc!=VIREO_OK) {
        if(rc!=VIREO_RESULT_PROTOCOL) s->infrastructure_result=rc;
        return rc;
    }
    if(slot->closing) return VIREO_OK;
    if(mh && mh->state) {
        rc=vireo_mkdir_reactor_finish_head(s,slot,p); if(rc!=VIREO_OK) return rc;
    } else if(lh && lh->state) {
        rc=vireo_list_reactor_finish_head(s,slot,p); if(rc!=VIREO_OK) return rc;
    } else if(slot->root_head.state) {
        rc=vireo_root_reactor_finish_head(s,slot,p); if(rc!=VIREO_OK) return rc;
    } else if(slot->stat_head.state) {
        rc=vireo_stat_reactor_finish_head(s,slot,p); if(rc!=VIREO_OK) return rc;
    } else if(slot->head.state!=VIREO_AUTH_REQUEST_HEAD_EMPTY) {
        rc=finish_head(s,slot,p); if(rc!=VIREO_OK) return rc;
    } else if(!s->quiescing) {
        vireo_connection_frame_view_t view;
        vireo_connection_frame_info_t frames;
        rc=peek_frame(s,slot,&view,&frames);
        if(rc!=VIREO_OK) return rc;
        if(frames.frame_count) {
            if(view.header.command!=VIREO_COMMAND_REGISTER && view.header.command!=VIREO_COMMAND_LOGIN &&
               view.header.command!=VIREO_COMMAND_LOGOUT && view.header.command!=VIREO_COMMAND_SESSION_RESUME &&
               !(s->stat_queue && view.header.command==VIREO_COMMAND_NODE_STAT) &&
               !(s->root_queue && view.header.command==VIREO_COMMAND_NODE_ROOT) &&
               !(s->list && view.header.command==VIREO_COMMAND_NODE_LIST) &&
               !(s->mkdir && view.header.command==VIREO_COMMAND_NODE_MKDIR))
                return VIREO_RESULT_PROTOCOL;
            if(view.header.command==VIREO_COMMAND_NODE_MKDIR) {
                rc=vireo_mkdir_reactor_head(s,slot,view,p); if(rc!=VIREO_OK) return rc;
            } else if(view.header.command==VIREO_COMMAND_NODE_LIST) {
                rc=vireo_list_reactor_head(s,slot,view,p); if(rc!=VIREO_OK) return rc;
            } else if(view.header.command==VIREO_COMMAND_NODE_ROOT) {
                rc=vireo_root_reactor_head(s,slot,view,p); if(rc!=VIREO_OK) return rc;
            } else if(view.header.command==VIREO_COMMAND_NODE_STAT) {
                rc=vireo_stat_reactor_head(s,slot,view,p); if(rc!=VIREO_OK) return rc;
            } else {
                size_t reserve_index=SIZE_MAX;
                if(s->stat_queue) {
                    rc=vireo_stat_reactor_reserve(s,slot->client,view.header.sequence,view.header.command,&reserve_index);
                    if(rc!=VIREO_OK) return rc;
                }
                if(s->mkdir && reserve_index==SIZE_MAX) {
                    rc=vireo_mkdir_reactor_reject_auth(s,slot,view,p); if(rc!=VIREO_OK) return rc;
                    goto activity;
                }
                uint64_t now=0,deadline=0;
                rc=vireo_clock_monotonic_now(&now,NULL);
                if(rc!=VIREO_OK) { if(reserve_index!=SIZE_MAX) s->expected[reserve_index]=(vireo_stat_expected_t){0};
                    if(s->stat_queue) s->infrastructure_result=rc;
                    return rc; }
                rc=vireo_checked_u64_add(now,s->o.request_timeout_ns,&deadline);
                if(rc!=VIREO_OK) { if(reserve_index!=SIZE_MAX) s->expected[reserve_index]=(vireo_stat_expected_t){0};
                    if(s->stat_queue) s->infrastructure_result=rc;
                    return rc; }
                vireo_auth_request_submit_options_t const o={s->o.task_allocation_budget,s->o.max_client_requests,
                    s->o.register_operation,s->o.login_operation,deadline,s->o.logout_operation,s->o.resume_operation};
                uint64_t utc=0; rc=utc_now(&utc);
                if(rc!=VIREO_OK) { if(reserve_index!=SIZE_MAX) s->expected[reserve_index]=(vireo_stat_expected_t){0};
                    if(s->stat_queue) s->infrastructure_result=rc;
                    return rc; }
                /* view至此结束借用，head重新peek并在消费前保存防重凭据。 */
                rc=vireo_auth_request_submit_read_head(s->r.server,slot->client,s->r.store,s->r.workers,
                    s->r.admission,now,s->r.sessions,utc,&o,NULL,&slot->head,&slot->task,&p->head);
                if(p->head.receipt.submit_report.submit_report.task_transferred) ++p->submitted;
                if(s->stat_queue) {
                    vireo_result_t const committed=vireo_stat_reactor_commit_auth(s,reserve_index,&slot->head.submit_report);
                    if(committed!=VIREO_OK) return committed;
                    vireo_async_request_report_t const *a=&slot->head.submit_report.submit_report;
                    if(rc!=VIREO_OK && (a->task_transferred || a->submit_report.record_retained)) {
                        s->infrastructure_result=rc; return rc;
                    }
                }
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
                if(slot->head.state==VIREO_AUTH_REQUEST_HEAD_EMPTY) { if(rc!=VIREO_OK) return rc; }
                else { rc=finish_head(s,slot,p); if(rc!=VIREO_OK) return rc; }
            }
        }
    }
activity:
    rc=vireo_auth_deadline_activity(s,slot,0,p->submitted!=submitted_before,p);
    if(rc!=VIREO_OK) { s->infrastructure_result=rc; return rc; }
    if(slot->closing) return VIREO_OK;
    rc=vireo_tls_connection_flow_refresh(tls,&flow,NULL); if(rc!=VIREO_OK) return rc;
    if(!sent && flow.priority_retry!=VIREO_TLS_IO_OPERATION_READ &&
       (flow.want_write || flow.priority_retry==VIREO_TLS_IO_OPERATION_WRITE)) {
        rc=vireo_tls_connection_send(tls,&s->o.send,&progress,NULL); if(rc!=VIREO_OK) return rc;
    }
    rc=vireo_tcp_server_client_tls_flow_refresh(s->r.server,slot->client,&sync,NULL); if(rc!=VIREO_OK) return rc;
    rc=vireo_tls_connection_io_inspect(tls,&io,NULL); if(rc!=VIREO_OK) return rc;
    if((slot->head.state!=VIREO_AUTH_REQUEST_HEAD_EMPTY || slot->stat_head.state || slot->root_head.state || (lh && lh->state) || (mh && mh->state)) &&
       io.write_size<=io.options.write_capacity-32)
        return vireo_tcp_server_schedule_client(s->r.server,slot->client,NULL);
    /* 仅完整帧安排业务续处理；半帧绝不因read_size非零忙排队。 */
    if(!s->quiescing && slot->head.state==VIREO_AUTH_REQUEST_HEAD_EMPTY && !slot->stat_head.state && !slot->root_head.state && (!lh || !lh->state) && (!mh || !mh->state) && io.read_size) {
        vireo_connection_frame_view_t next;
        vireo_connection_frame_info_t frames;
        rc=peek_frame(s,slot,&next,&frames);
        if(rc!=VIREO_OK) return rc;
        if(frames.frame_count) return vireo_tcp_server_schedule_client(s->r.server,slot->client,NULL);
    }
    if(io.read_eof && !io.read_size && !io.write_size && slot->head.state==VIREO_AUTH_REQUEST_HEAD_EMPTY && !slot->stat_head.state && !slot->root_head.state && (!lh || !lh->state) && (!mh || !mh->state)) {
        size_t count=0;
        rc=vireo_inflight_store_count_client(s->r.store,slot->client,&count,NULL); if(rc!=VIREO_OK) return rc;
        bool pending=false; vireo_completion_info_t info;
        if(s->completion) {
            rc=vireo_completion_inspect(s->completion,&info); if(rc!=VIREO_OK) return rc;
            pending=same(client_of(info.metadata.request),slot->client);
        }
        if(s->stat_completion) {
            rc=vireo_completion_inspect(s->stat_completion,&info); if(rc!=VIREO_OK) return rc;
            pending=pending || same(client_of(info.metadata.request),slot->client);
        }
        if(s->root_completion) {
            rc=vireo_completion_inspect(s->root_completion,&info); if(rc!=VIREO_OK) return rc;
            pending=pending || same(client_of(info.metadata.request),slot->client);
        }
        if(s->list && s->list->completion) {
            rc=vireo_completion_inspect(s->list->completion,&info); if(rc!=VIREO_OK) return rc;
            pending=pending || same(client_of(info.metadata.request),slot->client);
        }
        if(s->mkdir && s->mkdir->completion) {
            rc=vireo_completion_inspect(s->mkdir->completion,&info); if(rc!=VIREO_OK) return rc;
            pending=pending || same(client_of(info.metadata.request),slot->client);
        }
        if(!count && !pending) vireo_auth_service_close_slot(s,slot);
    }
    return VIREO_OK;
}
/** 每次ready只做握手或应用，不从握手同轮跳进认证。 */
static vireo_result_t turn(vireo_auth_service_t *s,client_slot_t *slot,vireo_auth_service_report_t *p)
{
    if(slot->closing) return VIREO_OK;
    vireo_result_t rc=vireo_auth_deadline_guard(s,slot,p);
    if(rc!=VIREO_OK) { s->infrastructure_result=rc; return rc; }
    if(slot->closing) return VIREO_OK;
    vireo_tls_connection_t *tls=NULL;
    rc=vireo_tcp_server_client_tls_borrow(s->r.server,slot->client,&tls,NULL);
    if(rc!=VIREO_OK) return rc;
    vireo_tls_connection_info_t connection;
    rc=vireo_tls_connection_inspect(tls,&connection,NULL); if(rc!=VIREO_OK) return rc;
    if(connection.handshake_state!=VIREO_TLS_HANDSHAKE_ESTABLISHED) {
        vireo_tcp_server_tls_handshake_info_t h;
        rc=vireo_tcp_server_client_tls_handshake_step(s->r.server,slot->client,&h,&p->tls_error);
        if(rc==VIREO_OK && h.application_ready) {
            rc=vireo_auth_deadline_start(s,slot);
            if(rc!=VIREO_OK) { vireo_auth_service_close_slot(s,slot); s->infrastructure_result=rc; return rc; }
            rc=vireo_tcp_server_schedule_client(s->r.server,slot->client,NULL);
        }
        return rc;
    }
    return application(s,slot,tls,p);
}
/** 一次提示读取和独立预算领取，提示计数不决定领取量；满响应只保原owner。 */
static vireo_result_t auth_completions(vireo_auth_service_t *s,vireo_auth_service_report_t *p)
{
    vireo_result_t rc;
    for(size_t i=0;i<s->o.max_completions;++i) {
        if(!s->completion) {
            vireo_completion_queue_transfer_report_t transfer;
            rc=vireo_completion_queue_try_pop(s->r.queue,&s->completion,&transfer);
            if(rc==VIREO_RESULT_NOT_FOUND || rc==VIREO_RESULT_CANCELLED || rc==VIREO_RESULT_BUSY) {
                if(!transfer.transferred) {
                    if(rc==VIREO_RESULT_BUSY) break;
                    return VIREO_OK;
                }
            }
            if(rc!=VIREO_OK) return rc;
        }
        vireo_completion_info_t info;
        rc=vireo_completion_inspect(s->completion,&info); if(rc!=VIREO_OK) return rc;
        client_slot_t *slot=find(s,client_of(info.metadata.request));
        if(slot && p->stopped) vireo_auth_service_close_slot(s,slot);
        if(slot) { rc=vireo_auth_deadline_guard(s,slot,p); if(rc!=VIREO_OK) return rc; }
        if(slot && slot->closing) { rc=discard(s); if(rc!=VIREO_OK) return rc; }
        else {
            if(s->stat_queue) { rc=vireo_stat_reactor_check_auth(s); if(rc!=VIREO_OK) return rc; }
            uint64_t now=0; rc=utc_now(&now); if(rc!=VIREO_OK) return rc;
            vireo_auth_response_consumer_options_t const o={s->o.register_operation,s->o.login_operation,s->o.logout_operation,s->o.resume_operation};
            rc=vireo_auth_response_consumer_step(s->r.server,s->r.store,s->r.sessions,&s->completion,
                &o,now,&s->receipt,&p->consumer);
            /* commit可能已成功而后续refresh失败；按真实bound前缀切换，不能漏计。 */
            if(slot && p->consumer.bound) {
                vireo_result_t const timer=vireo_auth_deadline_activity(s,slot,s->receipt.ticket.handle,false,p);
                if(timer!=VIREO_OK) return timer;
            }
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
        if(s->stat_queue && !s->completion) vireo_stat_reactor_forget(s,info.metadata.request);
        ++p->completions;
    }
    vireo_notifier_notify_outcome_t notified;
    return vireo_notifier_notify(s->r.notifier,&notified,NULL);
}

static vireo_result_t completions(vireo_auth_service_t *s,vireo_auth_service_report_t *p)
{
    uint64_t hints=0;
    vireo_result_t rc=vireo_notifier_consume(s->r.notifier,&hints,NULL); if(rc!=VIREO_OK) return rc;
    if(!s->stat_queue) return auth_completions(s,p);
    if(s->root_queue) {
        unsigned const queues=s->mkdir?5u:s->list?4u:3u;
        unsigned const first=s->completion_cursor; s->completion_cursor=(first+1u)%queues;
        for(unsigned i=0;i<queues;++i) {
            unsigned const q=(first+i)%queues;
            rc=q==0?auth_completions(s,p):q==1?vireo_stat_reactor_completions(s,p):q==2?vireo_root_reactor_completions(s,p):q==3?vireo_list_reactor_completions(s,p):vireo_mkdir_reactor_completions(s,p);
            if(rc!=VIREO_OK) return rc;
        }
        return VIREO_OK;
    }
    bool const stat_first=s->stat_first; s->stat_first=!s->stat_first;
    rc=stat_first?vireo_stat_reactor_completions(s,p):auth_completions(s,p);
    if(rc!=VIREO_OK) return rc;
    return stat_first?auth_completions(s,p):vireo_stat_reactor_completions(s,p);
}
static vireo_result_t create(vireo_auth_service_resources_t const *resources,
    vireo_auth_service_options_t const *options,vireo_completion_queue_t *stat_queue,uint32_t stat_operation,
    vireo_completion_queue_t *root_queue,uint32_t root_operation,
    vireo_completion_queue_t *list_queue,uint32_t list_operation,size_t list_bytes,
    vireo_completion_queue_t *mkdir_queue,uint32_t mkdir_operation,vireo_auth_service_t **owner)
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
    if(stat_queue && (!stat_operation || stat_queue==r.queue || stat_operation==o.register_operation ||
        stat_operation==o.login_operation || stat_operation==o.logout_operation || stat_operation==o.resume_operation))
        return done(VIREO_RESULT_INVALID_ARGUMENT,saved);
    if(root_queue && (!stat_queue || !root_operation || root_queue==r.queue || root_queue==stat_queue ||
        root_operation==stat_operation || root_operation==o.register_operation || root_operation==o.login_operation ||
        root_operation==o.logout_operation || root_operation==o.resume_operation)) return done(VIREO_RESULT_INVALID_ARGUMENT,saved);
    if(list_queue && (!root_queue || !list_operation || !list_bytes || list_queue==r.queue || list_queue==stat_queue ||
        list_queue==root_queue || list_operation==stat_operation || list_operation==root_operation ||
        list_operation==o.register_operation || list_operation==o.login_operation || list_operation==o.logout_operation ||
        list_operation==o.resume_operation)) return done(VIREO_RESULT_INVALID_ARGUMENT,saved);
    if(mkdir_queue && (!list_queue || !mkdir_operation || mkdir_queue==r.queue || mkdir_queue==stat_queue ||
        mkdir_queue==root_queue || mkdir_queue==list_queue || mkdir_operation==stat_operation || mkdir_operation==root_operation ||
        mkdir_operation==list_operation || mkdir_operation==o.register_operation || mkdir_operation==o.login_operation ||
        mkdir_operation==o.logout_operation || mkdir_operation==o.resume_operation)) return done(VIREO_RESULT_INVALID_ARGUMENT,saved);
    if(list_queue && (list_bytes<VIREO_DIRECTORY_LIST_COMPLETION_PAYLOAD_MAX || list_bytes>MEMORY_MAX)) return done(VIREO_RESULT_RANGE,saved);
    vireo_tcp_server_info_t root; vireo_tcp_server_tls_info_t tls;
    vireo_inflight_store_info_t inflight; vireo_thread_pool_info_t workers; vireo_completion_queue_info_t queue;
    vireo_result_t rc=vireo_tcp_server_inspect(r.server,&root); if(rc!=VIREO_OK) return done(rc,saved);
    rc=vireo_tcp_server_tls_inspect(r.server,&tls,NULL); if(rc!=VIREO_OK) return done(rc,saved);
    rc=vireo_inflight_store_inspect(r.store,&inflight); if(rc!=VIREO_OK) return done(rc,saved);
    rc=vireo_thread_pool_inspect(r.workers,&workers); if(rc!=VIREO_OK) return done(rc,saved);
    rc=vireo_completion_queue_inspect(r.queue,&queue); if(rc!=VIREO_OK) return done(rc,saved);
    if(stat_queue) {
        vireo_completion_queue_info_t stat;
        rc=vireo_completion_queue_inspect(stat_queue,&stat); if(rc!=VIREO_OK) return done(rc,saved);
        if(stat.closed) return done(VIREO_RESULT_CANCELLED,saved);
        if(!stat.wait_prepared) return done(VIREO_RESULT_NOT_FOUND,saved);
        if(stat.count || queue.count) return done(VIREO_RESULT_BUSY,saved);
    }
    if(root_queue) {
        vireo_completion_queue_info_t q;
        rc=vireo_completion_queue_inspect(root_queue,&q); if(rc!=VIREO_OK) return done(rc,saved);
        if(q.closed) return done(VIREO_RESULT_CANCELLED,saved);
        if(!q.wait_prepared) return done(VIREO_RESULT_NOT_FOUND,saved);
        if(q.count) return done(VIREO_RESULT_BUSY,saved);
    }
    if(list_queue) {
        vireo_completion_queue_info_t q;
        rc=vireo_completion_queue_inspect(list_queue,&q); if(rc!=VIREO_OK) return done(rc,saved);
        if(q.closed) return done(VIREO_RESULT_CANCELLED,saved);
        if(!q.wait_prepared) return done(VIREO_RESULT_NOT_FOUND,saved);
        if(q.count) return done(VIREO_RESULT_BUSY,saved);
    }
    if(mkdir_queue) {
        vireo_completion_queue_info_t q;
        rc=vireo_completion_queue_inspect(mkdir_queue,&q); if(rc!=VIREO_OK) return done(rc,saved);
        if(q.closed) return done(VIREO_RESULT_CANCELLED,saved);
        if(!q.wait_prepared) return done(VIREO_RESULT_NOT_FOUND,saved);
        if(q.count) return done(VIREO_RESULT_BUSY,saved);
    }
    if(root.stop_requested || workers.stop_requested || queue.closed) return done(VIREO_RESULT_CANCELLED,saved);
    if(!root.listener_owned || !root.listener_bound || !queue.wait_prepared) return done(VIREO_RESULT_NOT_FOUND,saved);
    if(root.connection_count || inflight.count || !workers.execution_enabled || !workers.configured ||
       root.processing_active || root.driving_active || root.scheduling_active || root.serving_active ||
       root.shutdown_active || root.closing_active) return done(VIREO_RESULT_BUSY,saved);
    if(o.max_clients>root.connection_capacity || o.admit.max_accepts>root.connection_capacity ||
       o.max_completions>65536 || o.cleanup_slots>65536 || o.max_client_requests>inflight.capacity ||
       o.task_allocation_budget>MEMORY_MAX || o.max_memory_bytes>MEMORY_MAX ||
       tls.options.io.read_capacity<(mkdir_queue?VIREO_NODE_MKDIR_REQUEST_FRAME_MAX:VIREO_AUTH_REQUEST_FRAME_MAX) ||
       tls.options.io.max_read_unit_bytes<(mkdir_queue?VIREO_NODE_MKDIR_REQUEST_FRAME_MAX:VIREO_AUTH_REQUEST_FRAME_MAX) ||
       (mkdir_queue && tls.options.io.read_low<VIREO_NODE_MKDIR_REQUEST_FRAME_MAX-1) || tls.options.io.write_capacity<(list_queue?VIREO_NODE_LIST_RESPONSE_FRAME_MAX:stat_queue?VIREO_NODE_STAT_RESPONSE_FRAME_MAX:104) ||
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
    size_t expected_capacity=0,expected_bytes=0;
    if(stat_queue) {
        if(rc==VIREO_OK) rc=vireo_checked_size_add(inflight.capacity,mkdir_queue?5:list_queue?4:root_queue?3:2,&expected_capacity);
        if(rc==VIREO_OK) rc=vireo_checked_size_mul(expected_capacity,sizeof(vireo_stat_expected_t),&expected_bytes);
        if(rc==VIREO_OK) rc=vireo_checked_size_add(total,expected_bytes,&total);
        if(rc!=VIREO_OK) return done(rc,saved);
    }
    size_t list_heads_bytes=0,list_requests_bytes=0;
    if(list_queue) {
        rc=vireo_checked_size_mul(root.connection_capacity,sizeof(vireo_list_head_t),&list_heads_bytes);
        if(rc==VIREO_OK) rc=vireo_checked_size_mul(expected_capacity,sizeof(vireo_node_list_request_t),&list_requests_bytes);
        if(rc==VIREO_OK) rc=vireo_checked_size_add(total,sizeof(vireo_list_reactor_state_t),&total);
        if(rc==VIREO_OK) rc=vireo_checked_size_add(total,list_heads_bytes,&total);
        if(rc==VIREO_OK) rc=vireo_checked_size_add(total,list_requests_bytes,&total);
        if(rc!=VIREO_OK) return done(rc,saved);
    }
    size_t mkdir_heads_bytes=0,mkdir_requests_bytes=0;
    if(mkdir_queue) {
        rc=vireo_checked_size_mul(root.connection_capacity,sizeof(vireo_mkdir_head_t),&mkdir_heads_bytes);
        if(rc==VIREO_OK) rc=vireo_checked_size_mul(expected_capacity,sizeof(vireo_mkdir_request_key_t),&mkdir_requests_bytes);
        if(rc==VIREO_OK) rc=vireo_checked_size_add(total,sizeof(vireo_mkdir_reactor_state_t),&total);
        if(rc==VIREO_OK) rc=vireo_checked_size_add(total,mkdir_heads_bytes,&total);
        if(rc==VIREO_OK) rc=vireo_checked_size_add(total,mkdir_requests_bytes,&total);
        if(rc!=VIREO_OK) return done(rc,saved);
    }
    if(total>o.max_memory_bytes) return done(VIREO_RESULT_RANGE,saved);
    /* 各数组需本类型对齐；分开calloc避免控制块尾部不同类型对齐假设。 */
    vireo_auth_service_t *s=calloc(1,sizeof(*s)); if(!s) return done(VIREO_RESULT_NO_MEMORY,saved);
    s->slots=calloc(root.connection_capacity,sizeof(*s->slots));
    s->ready=calloc(o.max_clients,sizeof(*s->ready)); s->accepted=calloc(o.admit.max_accepts,sizeof(*s->accepted));
    if(!s->slots || !s->ready || !s->accepted) { rc=VIREO_RESULT_NO_MEMORY; goto fail; }
    s->r=r; s->o=o; s->capacity=root.connection_capacity;
    s->stat_queue=stat_queue; s->stat_operation=stat_operation;
    s->root_queue=root_queue; s->root_operation=root_operation;
    if(root_queue) vireo_root_reactor_default_ops(&s->root_ops);
    s->expected_capacity=expected_capacity;
    if(stat_queue) {
        s->expected=calloc(expected_capacity,sizeof(*s->expected));
        if(!s->expected) { rc=VIREO_RESULT_NO_MEMORY; goto fail; }
        vireo_stat_reactor_default_ops(&s->stat_ops);
    }
    if(list_queue) {
        s->list=calloc(1,sizeof(*s->list));
        if(!s->list) { rc=VIREO_RESULT_NO_MEMORY; goto fail; }
        s->list->heads=calloc(1,list_heads_bytes); s->list->requests=calloc(1,list_requests_bytes);
        if(!s->list->heads || !s->list->requests) { rc=VIREO_RESULT_NO_MEMORY; goto fail; }
        s->list->queue=list_queue; s->list->operation=list_operation; s->list->byte_budget=list_bytes;
        vireo_list_reactor_default_ops(&s->list->ops);
    }
    if(mkdir_queue) {
        s->mkdir=calloc(1,sizeof(*s->mkdir));
        if(!s->mkdir) { rc=VIREO_RESULT_NO_MEMORY; goto fail; }
        s->mkdir->heads=calloc(1,mkdir_heads_bytes); s->mkdir->requests=calloc(1,mkdir_requests_bytes);
        if(!s->mkdir->heads || !s->mkdir->requests) { rc=VIREO_RESULT_NO_MEMORY; goto fail; }
        s->mkdir->queue=mkdir_queue; s->mkdir->operation=mkdir_operation;
        vireo_mkdir_reactor_default_ops(&s->mkdir->ops);
    }
    rc=vireo_notifier_server_register(r.server,r.notifier,&s->handle,NULL); if(rc!=VIREO_OK) goto fail;
    *owner=s; return done(VIREO_OK,saved);
fail:
    if(s->mkdir) { free(s->mkdir->requests); free(s->mkdir->heads); free(s->mkdir); }
    if(s->list) { free(s->list->requests); free(s->list->heads); free(s->list); }
    free(s->expected); free(s->accepted); free(s->ready); free(s->slots); free(s); return done(rc,saved);
}

vireo_result_t vireo_auth_service_create(vireo_auth_service_resources_t const *r,
    vireo_auth_service_options_t const *o,vireo_auth_service_t **owner)
{ return create(r,o,NULL,0,NULL,0,NULL,0,0,NULL,0,owner); }
vireo_result_t vireo_directory_stat_reactor_create(vireo_auth_service_resources_t const *r,
    vireo_auth_service_options_t const *o,vireo_completion_queue_t *queue,uint32_t operation,vireo_auth_service_t **owner)
{ return queue?create(r,o,queue,operation,NULL,0,NULL,0,0,NULL,0,owner):VIREO_RESULT_INVALID_ARGUMENT; }
vireo_result_t vireo_directory_root_reactor_create(vireo_auth_service_resources_t const *r,
    vireo_auth_service_options_t const *o,vireo_completion_queue_t *sq,uint32_t sop,
    vireo_completion_queue_t *rq,uint32_t rop,vireo_auth_service_t **owner)
{ return sq && rq?create(r,o,sq,sop,rq,rop,NULL,0,0,NULL,0,owner):VIREO_RESULT_INVALID_ARGUMENT; }
vireo_result_t vireo_directory_list_reactor_create(vireo_auth_service_resources_t const *r,
    vireo_auth_service_options_t const *o,vireo_completion_queue_t *sq,uint32_t sop,
    vireo_completion_queue_t *rq,uint32_t rop,vireo_completion_queue_t *lq,uint32_t lop,
    size_t bytes,vireo_auth_service_t **owner)
{ return sq && rq && lq?create(r,o,sq,sop,rq,rop,lq,lop,bytes,NULL,0,owner):VIREO_RESULT_INVALID_ARGUMENT; }
vireo_result_t vireo_directory_mkdir_reactor_create(vireo_auth_service_resources_t const *r,
    vireo_auth_service_options_t const *o,vireo_completion_queue_t *sq,uint32_t sop,
    vireo_completion_queue_t *rq,uint32_t rop,vireo_completion_queue_t *lq,uint32_t lop,
    size_t bytes,vireo_completion_queue_t *mq,uint32_t mop,vireo_auth_service_t **owner)
{ return sq && rq && lq && mq?create(r,o,sq,sop,rq,rop,lq,lop,bytes,mq,mop,owner):VIREO_RESULT_INVALID_ARGUMENT; }
vireo_result_t vireo_directory_mkdir_reactor_inspect(vireo_auth_service_t const *s,vireo_directory_mkdir_reactor_report_t *out)
{
    int const saved=errno;
    if(!s || !out) return done(VIREO_RESULT_INVALID_ARGUMENT,saved);
    if(!s->mkdir) return done(VIREO_RESULT_NOT_FOUND,saved);
    *out=s->mkdir->report; return done(VIREO_OK,saved);
}
vireo_result_t vireo_directory_list_reactor_inspect(vireo_auth_service_t const *s,vireo_directory_list_reactor_report_t *out)
{
    int const saved=errno;
    if(!s || !out) return done(VIREO_RESULT_INVALID_ARGUMENT,saved);
    if(!s->list) return done(VIREO_RESULT_NOT_FOUND,saved);
    *out=s->list->report; return done(VIREO_OK,saved);
}
vireo_result_t vireo_directory_root_reactor_inspect(vireo_auth_service_t const *s,vireo_directory_root_reactor_report_t *out)
{
    int const saved=errno;
    if(!s || !out) return done(VIREO_RESULT_INVALID_ARGUMENT,saved);
    if(!s->root_queue) return done(VIREO_RESULT_NOT_FOUND,saved);
    *out=s->root_report; return done(VIREO_OK,saved);
}
vireo_result_t vireo_directory_stat_reactor_inspect(vireo_auth_service_t const *s,vireo_directory_stat_reactor_report_t *out)
{
    int const saved=errno;
    if(!s || !out) return done(VIREO_RESULT_INVALID_ARGUMENT,saved);
    if(!s->stat_queue) return done(VIREO_RESULT_NOT_FOUND,saved);
    *out=s->stat_report; return done(VIREO_OK,saved);
}
vireo_result_t vireo_auth_service_once(vireo_auth_service_t *s,int timeout,vireo_auth_service_report_t *out)
{
    int const saved=errno; vireo_auth_service_report_t p={0}; vireo_result_t rc=VIREO_OK;
    if(!s || !out || timeout<0) { rc=VIREO_RESULT_INVALID_ARGUMENT; goto finish; }
    if(timeout>1000) { rc=VIREO_RESULT_RANGE; goto finish; }
    if(s->mkdir) s->mkdir->report=(vireo_directory_mkdir_reactor_report_t){0};
    if(s->list) s->list->report=(vireo_directory_list_reactor_report_t){0};
    s->root_report=(vireo_directory_root_reactor_report_t){0};
    s->stat_report=(vireo_directory_stat_reactor_report_t){0}; s->infrastructure_result=VIREO_OK;
    vireo_tcp_server_info_t root;
    rc=vireo_tcp_server_inspect(s->r.server,&root); if(rc!=VIREO_OK) goto finish;
    if(root.processing_active || root.driving_active || root.scheduling_active || root.serving_active ||
       root.shutdown_active || root.closing_active) { rc=VIREO_RESULT_BUSY; goto finish; }
    p.stopped=root.stop_requested; if(p.stopped) s->quiescing=true;
    if(!p.stopped) { rc=vireo_auth_deadline_pump(s,&p); if(rc!=VIREO_OK) goto finish; }
    /* 清理游标按槽公平轮转；空槽同样消耗扫描预算。 */
    for(size_t i=0;i<s->o.max_clients;++i) {
        client_slot_t *slot=&s->slots[s->sweep]; s->sweep=(s->sweep+1)%s->capacity;
        if(!slot->client.pool_id) continue;
        if(p.stopped) vireo_auth_service_close_slot(s,slot);
        rc=vireo_auth_deadline_guard(s,slot,&p); if(rc!=VIREO_OK) goto finish;
        if(slot->closing) { rc=cleanup(s,slot,&p); if(rc!=VIREO_OK) goto finish; }
    }
    if(p.timer_work_pending) goto finish;
    rc=completions(s,&p); if(rc!=VIREO_OK) goto finish;
    if(p.stopped) { s->ready_count=0; s->ready_next=0; goto finish; }
    vireo_tcp_server_tls_admission_info_t pressure;
    if(s->quiescing) rc=vireo_tcp_server_set_listener_read_enabled(s->r.server,false,NULL);
    else rc=vireo_tcp_server_tls_admission_refresh(s->r.server,&pressure,NULL);
    if(rc!=VIREO_OK) goto finish;
    if(s->ready_next==s->ready_count) {
        s->ready_count=0; s->ready_next=0; p.poll_called=true;
        /* FIFO阻塞须等网络可写；pending owner本身不等于可推进，避免慢端空转。 */
        int wait=(p.completions || p.released || s->closing_count)?0:timeout;
        if(s->deadline_wheel) {
            uint64_t now=0; rc=s->deadline_now(&now,NULL); if(rc!=VIREO_OK) goto post;
            vireo_timer_loop_wait_plan_t plan;
            rc=vireo_timer_loop_plan_wait(s->deadline_wheel,now,wait,&plan); if(rc!=VIREO_OK) goto post;
            wait=plan.timeout_ms;
        }
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
    rc=vireo_auth_deadline_pump(s,&p); if(rc!=VIREO_OK || p.timer_work_pending) goto post;
    while(s->ready_next<s->ready_count) {
        vireo_connection_pool_lease_t const c=s->ready[s->ready_next++].client;
        client_slot_t *slot=find(s,c); if(!slot) continue; ++p.client_turns;
        vireo_result_t const local=turn(s,slot,&p);
        if(s->infrastructure_result!=VIREO_OK) {
            /* 保留selected恢复点：consume失败后即使无新socket边沿，也只能补原head。 */
            --s->ready_next; rc=s->infrastructure_result; goto post;
        }
        if(local!=VIREO_OK) client_error(s,&p,slot,local);
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
    if(s) {
        p.quiescing=s->quiescing;
        if(s->mkdir) { s->mkdir->report.completion_pending=s->mkdir->completion!=NULL; s->mkdir->report.expected_requests=s->expected_count; }
        if(s->list) { s->list->report.completion_pending=s->list->completion!=NULL; s->list->report.expected_requests=s->expected_count; }
        s->root_report.completion_pending=s->root_completion!=NULL;
        s->root_report.expected_requests=s->expected_count;
        s->stat_report.completion_pending=s->stat_completion!=NULL;
        s->stat_report.expected_requests=s->expected_count;
    }
    if(out) *out=p;
    return done(rc,saved);
}
vireo_result_t vireo_auth_service_quiesce(vireo_auth_service_t *s)
{ if(!s) return VIREO_RESULT_INVALID_ARGUMENT; s->quiescing=true; return VIREO_OK; }
vireo_result_t vireo_auth_service_disconnect(vireo_auth_service_t *s,vireo_connection_pool_lease_t c)
{
    if(!s) return VIREO_RESULT_INVALID_ARGUMENT;
    client_slot_t *slot=find(s,c); if(!slot) return VIREO_RESULT_NOT_FOUND;
    vireo_auth_service_close_slot(s,slot); return VIREO_OK;
}
vireo_result_t vireo_auth_service_destroy(vireo_auth_service_t **owner)
{
    int const saved=errno;
    if(!owner) return done(VIREO_RESULT_INVALID_ARGUMENT,saved);
    vireo_auth_service_t *s=*owner; if(!s) return done(VIREO_OK,saved);
    if(s->active || s->completion || s->receipt.state || s->stat_completion || s->stat_receipt.state || s->root_completion || s->root_receipt.state || (s->list && (s->list->completion || s->list->receipt.state)) || (s->mkdir && (s->mkdir->completion || s->mkdir->receipt.state)) || s->expected_count || s->ready_next<s->ready_count) return done(VIREO_RESULT_BUSY,saved);
    vireo_result_t rc=vireo_notifier_server_unregister(s->r.server,&s->handle,NULL); if(rc!=VIREO_OK) return done(rc,saved);
    if(s->list) {
        (void)vireo_secure_clear(s->list->requests,s->expected_capacity*sizeof(*s->list->requests));
        (void)vireo_secure_clear(s->list->heads,s->capacity*sizeof(*s->list->heads));
        free(s->list->requests); free(s->list->heads);
        (void)vireo_secure_clear(s->list,sizeof(*s->list)); free(s->list);
    }
    if(s->mkdir) {
        (void)vireo_secure_clear(s->mkdir->requests,s->expected_capacity*sizeof(*s->mkdir->requests));
        (void)vireo_secure_clear(s->mkdir->heads,s->capacity*sizeof(*s->mkdir->heads));
        free(s->mkdir->requests); free(s->mkdir->heads);
        (void)vireo_secure_clear(s->mkdir,sizeof(*s->mkdir)); free(s->mkdir);
    }
    free(s->deadline_routes); free(s->expected); free(s->accepted); free(s->ready); free(s->slots); free(s); *owner=NULL;
    return done(VIREO_OK,saved);
}
