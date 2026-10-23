/* PROJECT : VIREO
 * FILE : auth_service_deadline.c
 * AUTHOR : bitofux
 * DATE : 2026-10-23
 * BRIEF : 认证连接期限策略；复用公开时间轮和完整客户绑定，不接管worker。 */
#define _POSIX_C_SOURCE 200809L
#include "directory_stat_reactor_internal.h"
#include <vireo/base/checked.h>
#include <vireo/net/timer_loop.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

#define MEMORY_MAX ((size_t)67108864)
static bool same_client(vireo_connection_pool_lease_t a,vireo_connection_pool_lease_t b)
{ return a.pool_id==b.pool_id && a.slot_index==b.slot_index && a.generation==b.generation; }
static bool same_timer(vireo_timer_handle_t a,vireo_timer_handle_t b)
{ return a.owner_id==b.owner_id && a.slot_index==b.slot_index && a.generation==b.generation; }
static uint64_t earliest(vireo_auth_client_deadline_t const *d)
{ return d->frame_ns && d->frame_ns<d->phase_ns?d->frame_ns:d->phase_ns; }

/** 在原期限已到时只关一次，绝不允许先重排再判过期。 */
static void expire(vireo_auth_service_t *s,client_slot_t *slot,vireo_auth_service_report_t *p)
{
    if(slot->closing) return;
    vireo_auth_client_deadline_t const *d=&slot->deadline;
    if(d->frame_ns && d->frame_ns<=d->phase_ns) ++p->frame_timeouts;
    else if(d->authenticated_handle) ++p->idle_timeouts;
    else ++p->unauthenticated_timeouts;
    vireo_auth_service_close_slot(s,slot);
    if(p->first_client_result==VIREO_OK) {
        p->first_client_result=VIREO_RESULT_TIMEOUT; p->first_failed_client=slot->client;
    }
}
/** 所有算术先于重排；新timer成功后只保存完整数值反查，不再引入失败步骤。 */
static vireo_result_t sync_timer(vireo_auth_service_t *s,client_slot_t *slot,uint64_t now)
{
    vireo_auth_client_deadline_t *d=&slot->deadline;
    if(d->binding.timer.owner_id)
        return vireo_client_deadline_rearm(s->r.server,s->deadline_wheel,d->binding,now,earliest(d),NULL);
    vireo_result_t const rc=vireo_client_deadline_register(s->r.server,s->deadline_wheel,
        slot->client,now,earliest(d),&d->binding,NULL);
    if(rc==VIREO_OK) s->deadline_routes[d->binding.timer.slot_index]=d->binding;
    return rc;
}
vireo_result_t vireo_auth_service_enable_deadlines(vireo_auth_service_t *s,
    vireo_timer_wheel_t *wheel,vireo_auth_service_deadline_options_t const *o)
{
    int const saved=errno; vireo_result_t rc=VIREO_RESULT_INVALID_ARGUMENT;
    if(!s || !wheel || !o || !o->unauthenticated_timeout_ns || !o->frame_timeout_ns ||
       !o->authenticated_idle_timeout_ns || !o->advance.max_ticks || !o->advance.max_nodes ||
       !o->max_expired || !o->max_memory_bytes) goto done;
    rc=VIREO_RESULT_BUSY;
    if(s->deadline_wheel || s->active || s->ready_next<s->ready_count || s->quiescing) goto done;
    vireo_timer_wheel_registry_info_t registry;
    rc=vireo_timer_wheel_registry_inspect(wheel,&registry); if(rc!=VIREO_OK) goto done;
    rc=VIREO_RESULT_NOT_FOUND; if(!registry.prepared) goto done;
    rc=VIREO_RESULT_BUSY; if(registry.active_count) goto done;
    rc=VIREO_RESULT_RANGE;
    if(registry.capacity<s->capacity || o->advance.max_ticks>65536 || o->advance.max_nodes>65536 ||
       o->max_expired>65536 || o->max_memory_bytes>MEMORY_MAX) goto done;
    size_t bytes=0;
    rc=vireo_checked_size_mul(registry.capacity,sizeof(*s->deadline_routes),&bytes); if(rc!=VIREO_OK) goto done;
    rc=VIREO_RESULT_RANGE; if(bytes>o->max_memory_bytes) goto done;
    uint64_t now=0; rc=vireo_clock_monotonic_now(&now,NULL); if(rc!=VIREO_OK) goto done;
    vireo_timer_loop_wait_plan_t plan;
    rc=vireo_timer_loop_plan_wait(wheel,now,0,&plan); if(rc!=VIREO_OK) goto done;
    vireo_client_deadline_binding_t *routes=calloc(registry.capacity,sizeof(*routes));
    rc=VIREO_RESULT_NO_MEMORY; if(!routes) goto done;
    s->deadline_wheel=wheel; s->deadline_options=*o;
    s->deadline_routes=routes; s->deadline_capacity=registry.capacity;
    s->deadline_now=vireo_clock_monotonic_now; rc=VIREO_OK;
done:
    errno=saved; return rc;
}
vireo_result_t vireo_auth_deadline_start(vireo_auth_service_t *s,client_slot_t *slot)
{
    if(!s->deadline_wheel || slot->deadline.phase_ns) return VIREO_OK;
    uint64_t now=0,deadline=0;
    vireo_result_t rc=s->deadline_now(&now,NULL);
    if(rc==VIREO_OK) rc=vireo_checked_u64_add(now,s->deadline_options.unauthenticated_timeout_ns,&deadline);
    if(rc!=VIREO_OK) return rc;
    slot->deadline.phase_ns=deadline;
    rc=sync_timer(s,slot,now);
    if(rc!=VIREO_OK) slot->deadline.phase_ns=0;
    return rc;
}
vireo_result_t vireo_auth_deadline_guard(vireo_auth_service_t *s,client_slot_t *slot,vireo_auth_service_report_t *p)
{
    if(!s->deadline_wheel || !slot->deadline.phase_ns || slot->closing) return VIREO_OK;
    uint64_t now=0;
    vireo_result_t rc=s->deadline_now(&now,NULL); if(rc!=VIREO_OK) return rc;
    if(now>=earliest(&slot->deadline)) { expire(s,slot,p); return VIREO_OK; }
    if(!slot->deadline.authenticated_handle) return VIREO_OK;
    struct timespec t;
    if(clock_gettime(CLOCK_REALTIME,&t)!=0) return VIREO_RESULT_IO;
    if(t.tv_sec<0 || t.tv_nsec<0 || t.tv_nsec>=1000000000L) return VIREO_RESULT_INTERNAL;
    uint64_t utc=0;
    if((uintmax_t)t.tv_sec>UINT64_MAX/1000) return VIREO_RESULT_OVERFLOW;
    rc=vireo_checked_u64_add((uint64_t)t.tv_sec*1000,(uint64_t)t.tv_nsec/1000000,&utc);
    if(rc!=VIREO_OK) return rc;
    vireo_auth_session_identity_t identity;
    rc=vireo_auth_session_lookup(s->r.sessions,slot->client,slot->deadline.authenticated_handle,utc,&identity);
    if(rc==VIREO_OK) return rc;
    if(rc!=VIREO_RESULT_NOT_FOUND && rc!=VIREO_RESULT_TIMEOUT && rc!=VIREO_RESULT_CANCELLED) return rc;
    uint64_t deadline=0;
    rc=vireo_checked_u64_add(now,s->deadline_options.unauthenticated_timeout_ns,&deadline);
    if(rc!=VIREO_OK) return rc;
    vireo_auth_client_deadline_t const before=slot->deadline;
    slot->deadline.authenticated_handle=0; slot->deadline.phase_ns=deadline;
    rc=sync_timer(s,slot,now);
    if(rc!=VIREO_OK) slot->deadline=before;
    return rc;
}
vireo_result_t vireo_auth_deadline_activity(vireo_auth_service_t *s,client_slot_t *slot,
    uint32_t bound_handle,bool submitted,vireo_auth_service_report_t *p)
{
    if(!s->deadline_wheel) return VIREO_OK;
    vireo_result_t rc=vireo_auth_deadline_guard(s,slot,p); if(rc!=VIREO_OK || slot->closing) return rc;
    if(!bound_handle && (!submitted || !slot->deadline.authenticated_handle)) return VIREO_OK;
    uint64_t now=0,deadline=0;
    rc=s->deadline_now(&now,NULL);
    if(rc==VIREO_OK) rc=vireo_checked_u64_add(now,s->deadline_options.authenticated_idle_timeout_ns,&deadline);
    if(rc!=VIREO_OK) return rc;
    vireo_auth_client_deadline_t const before=slot->deadline;
    if(bound_handle) slot->deadline.authenticated_handle=bound_handle;
    slot->deadline.phase_ns=deadline;
    rc=sync_timer(s,slot,now);
    if(rc!=VIREO_OK) slot->deadline=before;
    return rc;
}
vireo_result_t vireo_auth_deadline_frames(vireo_auth_service_t *s,client_slot_t *slot,
    size_t old_size,vireo_auth_service_report_t *p)
{
    if(!s->deadline_wheel) return VIREO_OK;
    vireo_result_t rc=vireo_auth_deadline_guard(s,slot,p); if(rc!=VIREO_OK || slot->closing) return rc;
    unsigned char const *wire=NULL; size_t size=0,offset=0;
    rc=vireo_tcp_server_client_read_peek(s->r.server,slot->client,&wire,&size,NULL); if(rc!=VIREO_OK) return rc;
    /* 只找帧边界，不交接业务、不消费源；CRC/schema仍由原首帧链路校验。
     * 每步至少跳过32字节，整次受固定读FIFO容量限制；不分配view数组。 */
    while(size-offset>=VIREO_PROTOCOL_HEADER_SIZE) {
        vireo_protocol_header_t h; vireo_protocol_codec_issue_t issue;
        rc=vireo_protocol_header_decode(wire+offset,size-offset,&h,&issue);
        if(rc==VIREO_OK) rc=vireo_protocol_request_header_validate(&h,&issue);
        if(rc!=VIREO_OK) return rc;
        if(h.body_len>vireo_auth_command_frame_max(s,h.command)-VIREO_PROTOCOL_HEADER_SIZE) return VIREO_RESULT_PROTOCOL;
        size_t const bytes=VIREO_PROTOCOL_HEADER_SIZE+(size_t)h.body_len;
        if(bytes>size-offset) break;
        offset+=bytes;
    }
    uint64_t const old=slot->deadline.frame_ns;
    if(offset==size) slot->deadline.frame_ns=0;
    else if(!old || offset>=old_size) {
        uint64_t now=0,deadline=0;
        rc=s->deadline_now(&now,NULL);
        if(rc==VIREO_OK) rc=vireo_checked_u64_add(now,s->deadline_options.frame_timeout_ns,&deadline);
        if(rc!=VIREO_OK) return rc;
        slot->deadline.frame_ns=deadline;
    }
    if(old==slot->deadline.frame_ns) return VIREO_OK;
    uint64_t now=0; rc=s->deadline_now(&now,NULL);
    if(rc==VIREO_OK) rc=sync_timer(s,slot,now);
    if(rc!=VIREO_OK) slot->deadline.frame_ns=old;
    return rc;
}
vireo_result_t vireo_auth_deadline_cancel(vireo_auth_service_t *s,client_slot_t *slot)
{
    vireo_client_deadline_binding_t const binding=slot->deadline.binding;
    if(!binding.timer.owner_id) return VIREO_OK;
    vireo_result_t const rc=vireo_client_deadline_cancel(s->deadline_wheel,&slot->deadline.binding,NULL);
    if(rc==VIREO_OK) s->deadline_routes[binding.timer.slot_index]=(vireo_client_deadline_binding_t){0};
    return rc;
}
vireo_result_t vireo_auth_deadline_expired(vireo_auth_service_t *s,
    vireo_timer_wheel_expired_t const *event,vireo_auth_service_report_t *p)
{
    if(event->handle.slot_index>=s->deadline_capacity) return VIREO_OK;
    vireo_client_deadline_binding_t *binding=&s->deadline_routes[event->handle.slot_index];
    if(!same_timer(binding->timer,event->handle)) return VIREO_OK;
    vireo_client_deadline_binding_t const historical=*binding;
    *binding=(vireo_client_deadline_binding_t){0};
    if(historical.client.slot_index>=s->capacity) return VIREO_RESULT_INTERNAL;
    client_slot_t *slot=&s->slots[historical.client.slot_index];
    if(!same_client(slot->client,historical.client) || !same_timer(slot->deadline.binding.timer,event->handle)) return VIREO_OK;
    slot->deadline.binding=(vireo_client_deadline_binding_t){0};
    vireo_tcp_server_client_info_t info;
    vireo_result_t const rc=vireo_client_deadline_check_expired(s->r.server,historical,event,&info,NULL);
    if(rc==VIREO_RESULT_NOT_FOUND) return VIREO_OK;
    if(rc!=VIREO_OK) return rc;
    expire(s,slot,p); return VIREO_OK;
}
vireo_result_t vireo_auth_deadline_pump(vireo_auth_service_t *s,vireo_auth_service_report_t *p)
{
    if(!s->deadline_wheel) return VIREO_OK;
    uint64_t now=0;
    vireo_result_t rc=s->deadline_now(&now,NULL); if(rc!=VIREO_OK) return rc;
    vireo_timer_wheel_advance_report_t advanced;
    rc=vireo_timer_wheel_advance(s->deadline_wheel,now,s->deadline_options.advance,&advanced); if(rc!=VIREO_OK) return rc;
    for(size_t i=0;i<s->deadline_options.max_expired;++i) {
        vireo_timer_wheel_expired_t event;
        rc=vireo_timer_wheel_take_expired(s->deadline_wheel,&event);
        if(rc==VIREO_RESULT_NOT_FOUND) break;
        if(rc!=VIREO_OK) return rc;
        rc=vireo_auth_deadline_expired(s,&event,p); if(rc!=VIREO_OK) return rc;
    }
    vireo_timer_wheel_progress_t progress;
    rc=vireo_timer_wheel_progress_inspect(s->deadline_wheel,&progress); if(rc!=VIREO_OK) return rc;
    p->timer_work_pending=!progress.caught_up || progress.ready_count!=0;
    return VIREO_OK;
}
