/* PROJECT: VIREO; DATE: 2026-10-22; BRIEF: 严格关联/清理优先投影及独立VDC1。 */
#include "directory_stat_completion_internal.h"
#include <errno.h>
#include <string.h>

static void put64(unsigned char *p,uint64_t v)
{ for(size_t i=0;i<8;++i) p[i]=(unsigned char)(v>>((7-i)*8)); }
static uint64_t get64(const unsigned char *p)
{ uint64_t v=0; for(size_t i=0;i<8;++i) v=(v<<8)|p[i]; return v; }
static void put32(unsigned char *p,uint32_t v)
{ for(size_t i=0;i<4;++i) p[i]=(unsigned char)(v>>((3-i)*8)); }
static uint32_t get32(const unsigned char *p)
{ uint32_t v=0; for(size_t i=0;i<4;++i) v=(v<<8)|p[i]; return v; }
static bool zero(const unsigned char *p,size_t n)
{ for(size_t i=0;i<n;++i) if(p[i]) return false; return true; }
static bool known(vireo_result_t rc)
{ return rc>=VIREO_OK && rc<=VIREO_RESULT_INTERNAL; }
static bool node_zero(const vireo_mysql_node_value_t *n)
{
    return !n->id && !n->owner_id && !n->parent_id && !n->has_parent && !n->name_length &&
        !n->kind && !n->has_object_hash && !n->size && !n->created_at_ms && !n->updated_at_ms &&
        zero(n->name,sizeof(n->name)) && zero(n->object_hash,sizeof(n->object_hash));
}
static bool db_zero(const vireo_mysql_error_t *e)
{ return !e->stage && !e->system_error && !e->mysql_code && zero((const unsigned char *)e->sqlstate,sizeof(e->sqlstate)); }
static bool pool_zero(const vireo_mysql_pool_error_t *e)
{ return !e->stage && !e->pthread_code && !e->system_error && db_zero(&e->database); }
static bool error_zero(const vireo_mysql_node_error_t *e)
{
    return !e->stage && !e->system_errno && db_zero(&e->database) && pool_zero(&e->pool) &&
        !e->cleanup_result && !e->cleanup_stage && db_zero(&e->cleanup_database) && pool_zero(&e->cleanup_pool);
}
static bool report_zero(const vireo_mysql_node_report_t *r)
{ return !r->found && !r->issue && !r->rollback_confirmed && !r->cleanup_pending; }
static bool service_zero(const vireo_directory_stat_result_t *s)
{ return !s->outcome && node_zero(&s->node) && !s->repository_called && !s->repository_result && report_zero(&s->repository); }
static bool input_same(const vireo_directory_stat_input_t *a,const vireo_directory_stat_input_t *b)
{
    bool same=false;
    return vireo_task_metadata_same_request(a->metadata,b->metadata,&same)==VIREO_OK && same &&
        a->metadata.operation==b->metadata.operation && a->metadata.deadline_ns==b->metadata.deadline_ns &&
        a->actor.user_id==b->actor.user_id && a->actor.session_id==b->actor.session_id &&
        a->request.node_id==b->request.node_id && a->request.sequence==b->request.sequence &&
        a->request.session_handle==b->request.session_handle;
}
static bool pair(vireo_result_t rc,vireo_status_t status)
{
    switch(rc) {
    case VIREO_OK:return status==VIREO_STATUS_OK;
    case VIREO_RESULT_NOT_FOUND:return status==VIREO_STATUS_UNAUTHORIZED || status==VIREO_STATUS_NOT_FOUND;
    case VIREO_RESULT_BUSY:return status==VIREO_STATUS_BUSY || status==VIREO_STATUS_INTERNAL_ERROR;
    case VIREO_RESULT_TIMEOUT:return status==VIREO_STATUS_TIMEOUT || status==VIREO_STATUS_INTERNAL_ERROR;
    case VIREO_RESULT_CANCELLED:return status==VIREO_STATUS_UNAVAILABLE || status==VIREO_STATUS_INTERNAL_ERROR;
    default:return known(rc) && status==VIREO_STATUS_INTERNAL_ERROR;
    }
}
/* 完整成功/拒绝才允许业务投影；其余非OK保留基础设施语义。 */
static bool project(const vireo_directory_stat_task_result_t *r,vireo_node_stat_response_t *out)
{
    if(!known(r->result) || r->stage<VIREO_DIRECTORY_STAT_TASK_CONTEXT ||
        r->stage>VIREO_DIRECTORY_STAT_TASK_SERVICE || r->request_issue!=VIREO_NODE_STAT_ISSUE_NONE) return false;
    const vireo_directory_stat_result_t *s=&r->service;
    const bool cleanup=r->error.cleanup_result!=VIREO_OK || s->repository.cleanup_pending;
    out->sequence=r->input.request.sequence;
    out->status=VIREO_STATUS_INTERNAL_ERROR;
    if(r->stage!=VIREO_DIRECTORY_STAT_TASK_SERVICE) {
        if(r->result==VIREO_OK || r->result==VIREO_RESULT_NOT_FOUND || !service_zero(s) || !error_zero(&r->error)) return false;
    } else {
        if(!known(s->repository_result) || !known(r->error.cleanup_result)) return false;
        if(!s->repository_called && (!report_zero(&s->repository) || s->repository_result!=VIREO_OK)) return false;
        if(r->result==VIREO_OK || r->result==VIREO_RESULT_NOT_FOUND) {
            if(!s->repository_called || cleanup || !s->repository.rollback_confirmed ||
                s->repository_result!=r->result) return false;
            if(r->result==VIREO_OK) {
                const vireo_mysql_node_value_t *n=&s->node;
                if(s->outcome!=VIREO_DIRECTORY_STAT_FOUND || !s->repository.found || s->repository.issue ||
                    n->id!=r->input.request.node_id || n->owner_id!=r->input.actor.user_id) return false;
                if(n->kind!=VIREO_MYSQL_NODE_DIRECTORY && n->kind!=VIREO_MYSQL_NODE_FILE) return false;
                out->status=VIREO_STATUS_OK; out->session_handle=r->input.request.session_handle;
                out->metadata=(vireo_node_stat_metadata_t){.node_id=n->id,.has_parent=n->has_parent,
                    .parent_id=n->parent_id,.name_length=n->name_length,
                    .type=n->kind==VIREO_MYSQL_NODE_DIRECTORY?VIREO_NODE_STAT_DIRECTORY:VIREO_NODE_STAT_FILE,
                    .size=n->size,.created_at_ms=n->created_at_ms,.updated_at_ms=n->updated_at_ms,
                    .has_object_hash=n->has_object_hash};
                memcpy(out->metadata.name,n->name,sizeof(out->metadata.name));
                memcpy(out->metadata.object_hash,n->object_hash,sizeof(out->metadata.object_hash));
                return true; /* 原response encoder继续核名字/节点schema。 */
            }
            if(s->repository.found || !node_zero(&s->node)) return false;
            if(s->outcome==VIREO_DIRECTORY_STAT_UNAUTHORIZED && s->repository.issue==VIREO_MYSQL_NODE_AUTH_REJECTED)
                out->status=VIREO_STATUS_UNAUTHORIZED;
            else if(s->outcome==VIREO_DIRECTORY_STAT_NOT_FOUND && s->repository.issue==VIREO_MYSQL_NODE_NOT_FOUND)
                out->status=VIREO_STATUS_NOT_FOUND;
            else return false;
            return true;
        }
        if(s->outcome!=VIREO_DIRECTORY_STAT_NONE || !node_zero(&s->node)) return false;
    }
    if(!cleanup) {
        if(r->result==VIREO_RESULT_BUSY) out->status=VIREO_STATUS_BUSY;
        if(r->result==VIREO_RESULT_TIMEOUT) out->status=VIREO_STATUS_TIMEOUT;
        if(r->result==VIREO_RESULT_CANCELLED) out->status=VIREO_STATUS_UNAVAILABLE;
    }
    return true;
}

vireo_result_t vireo_directory_stat_completion_publish_with(const vireo_task_t *task,uint32_t op,
    const vireo_directory_stat_task_result_t *result,size_t budget,vireo_completion_queue_t *queue,
    vireo_notifier_t *notifier,vireo_completion_t **remaining,
    vireo_directory_stat_completion_publish_report_t *report,vireo_directory_stat_publish_fn publish)
{
    const int saved=errno; vireo_result_t rc=VIREO_RESULT_INVALID_ARGUMENT;
    if(report) memset(report,0,sizeof(*report));
    if(!task || !op || !result || !budget || !queue || !notifier || !remaining || *remaining || !report || !publish) goto done;
    vireo_directory_stat_input_t input; vireo_node_stat_issue_t issue;
    rc=vireo_directory_stat_task_read(task,op,&input,&issue); if(rc!=VIREO_OK) goto done;
    rc=VIREO_RESULT_PROTOCOL;
    if(!input_same(&input,&result->input)) goto done;
    report->task_matched=true;
    vireo_node_stat_response_t response={0}; rc=VIREO_RESULT_INVALID_ARGUMENT;
    if(!project(result,&response)) goto done;
    unsigned char payload[433]={0}; size_t size=0;
    rc=vireo_node_stat_response_encode(&response,payload+40,sizeof(payload)-40,&size);
    if(rc!=VIREO_OK) goto done;
    report->result_validated=true;
    memcpy(payload,"VDC1",4); put64(payload+8,input.actor.user_id); put64(payload+16,input.actor.session_id);
    put64(payload+24,input.request.node_id); put32(payload+32,input.request.session_handle); put32(payload+36,(uint32_t)size);
    report->publish_called=true;
    rc=publish(task,result->result,response.status,payload,40+size,budget,queue,notifier,remaining,&report->publication);
done: errno=saved; return rc;
}

vireo_result_t vireo_directory_stat_completion_publish(const vireo_task_t *task,uint32_t op,
    const vireo_directory_stat_task_result_t *result,size_t budget,vireo_completion_queue_t *queue,
    vireo_notifier_t *notifier,vireo_completion_t **remaining,vireo_directory_stat_completion_publish_report_t *report)
{ return vireo_directory_stat_completion_publish_with(task,op,result,budget,queue,notifier,remaining,report,vireo_completion_copy_wait_publish); }

vireo_result_t vireo_directory_stat_completion_decode(const vireo_completion_t *completion,uint32_t op,
    vireo_directory_stat_completion_outcome_t *out)
{
    const int saved=errno; vireo_result_t rc=VIREO_RESULT_INVALID_ARGUMENT;
    if(!completion || !op || !out) goto done;
    vireo_completion_info_t info; vireo_completion_payload_view_t view;
    rc=vireo_completion_inspect(completion,&info); if(rc!=VIREO_OK) goto done;
    rc=vireo_completion_borrow_payload(completion,&view); if(rc!=VIREO_OK) goto done;
    rc=VIREO_RESULT_PROTOCOL;
    if(view.size<72 || view.size>433 || info.metadata.request.operation!=op ||
        memcmp(view.data,"VDC1\0\0\0\0",8)) goto done;
    const uint32_t size=get32(view.data+36);
    if(size<32 || size>393 || view.size!=40+(size_t)size) goto done;
    vireo_directory_stat_completion_outcome_t next={.metadata=info.metadata,
        .actor={get64(view.data+8),get64(view.data+16)},.requested_node_id=get64(view.data+24),
        .request_session_handle=get32(view.data+32)};
    if(!next.actor.user_id || !next.actor.session_id || !next.requested_node_id || !next.request_session_handle) goto done;
    vireo_node_stat_issue_t issue;
    rc=vireo_node_stat_response_decode(view.data+40,size,&next.response,&issue); if(rc!=VIREO_OK) goto done;
    rc=VIREO_RESULT_PROTOCOL;
    if(next.response.sequence!=info.metadata.request.route.request_sequence ||
        next.response.status!=info.metadata.suggested_status || !pair(info.metadata.result,next.response.status)) goto done;
    if(next.response.status==VIREO_STATUS_OK && (next.response.session_handle!=next.request_session_handle ||
        next.response.metadata.node_id!=next.requested_node_id)) goto done;
    *out=next; rc=VIREO_OK;
done: errno=saved; return rc;
}
