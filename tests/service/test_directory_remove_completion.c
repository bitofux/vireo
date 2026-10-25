/* Result projection and independent completion decoding. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "directory_remove_completion_internal.h"

static vireo_task_metadata_t meta(void) {
    return (vireo_task_metadata_t){.route={1,0,3,11},.request_instance_id=9,.operation=404,.deadline_ns=100};
}
static void round_trip(const char *label, vireo_task_t *task, vireo_directory_remove_task_result_t *result,
                        vireo_status_t status, vireo_completion_queue_t *queue,
                        vireo_notifier_t *notifier) {
    vireo_completion_t *left=NULL, *completion=NULL;
    vireo_directory_remove_completion_publish_report_t report;
    errno=EDOM;
    vireo_result_t rc=vireo_directory_remove_completion_publish(task,404,result,4096,queue,notifier,&left,&report);
    if(rc!=VIREO_OK) fprintf(stderr,"%s publish rc=%d outcome=%d result=%d stage=%d repo=%d issue=%d commit=%d effect=%d rollback=%d\n",label,rc,result->service.outcome,result->result,result->stage,result->service.repository_called,result->service.repository.issue,result->service.repository.commit,result->service.repository.effect,result->service.repository.rollback_confirmed);
    assert(rc==VIREO_OK);
    assert(errno==EDOM && report.result_validated && report.publish_called && !left);
    vireo_completion_queue_transfer_report_t transfer;
    assert(vireo_completion_queue_try_pop(queue,&completion,&transfer)==VIREO_OK);
    vireo_directory_remove_completion_outcome_t out;
    assert(vireo_directory_remove_completion_decode(completion,404,&out)==VIREO_OK && errno==EDOM);
    assert(out.response.status==status && out.request_node_id==123 && out.request_session_handle==9);
    assert(!memcmp(out.request_idempotency_key,result->input.request.idempotency_key,16));
    if (status==VIREO_STATUS_OK) {
        assert(out.response.node_id==123 && out.response.session_handle==9);
        assert(!memcmp(out.response.idempotency_key,result->input.request.idempotency_key,16));
    } else assert(!out.response.node_id && !out.response.session_handle);
    vireo_directory_remove_completion_outcome_t saved;
    memset(&out,0xa5,sizeof(out)); memcpy(&saved,&out,sizeof(out));
    assert(vireo_directory_remove_completion_decode(completion,405,&out)==VIREO_RESULT_PROTOCOL);
    assert(!memcmp(&saved,&out,sizeof(out)));
    assert(vireo_completion_destroy(&completion)==VIREO_OK);
}
int main(void) {
    vireo_node_remove_request_t q={.sequence=11,.session_handle=9,.node_id=123};
    for(size_t i=0;i<16;i++) q.idempotency_key[i]=(unsigned char)(i+1);
    unsigned char wire[64]; size_t n=0;
    assert(vireo_node_remove_request_encode(&q,wire,64,&n)==VIREO_OK);
    vireo_mysql_node_actor_t actor={7,51}; vireo_task_t *task=NULL;
    assert(vireo_directory_remove_task_create(meta(),404,wire,64,&actor,4096,NULL,&task)==VIREO_OK);
    vireo_directory_remove_task_result_t base={.stage=VIREO_DIRECTORY_REMOVE_TASK_SERVICE,.result=VIREO_OK};
    assert(vireo_directory_remove_task_read(task,404,&base.input,&base.request_issue)==VIREO_OK);
    base.service=(vireo_directory_remove_result_t){.outcome=VIREO_DIRECTORY_REMOVE_APPLIED,
        .node_id=123,.audit_id=9,.repository_called=true,.repository_result=VIREO_OK,
        .repository={.commit=VIREO_MYSQL_NODE_SOFT_DELETE_COMMITTED,
        .effect=VIREO_MYSQL_NODE_REMOVE_EFFECT_APPLIED,.node_id=123,.audit_id=9}};
    memcpy(base.service.idempotency_key,q.idempotency_key,16);
    vireo_completion_queue_t *queue=NULL; vireo_notifier_t *notifier=NULL;
    vireo_completion_queue_options_t qo={1,65536}; vireo_notifier_options_t no={4096};
    assert(vireo_completion_queue_create(&qo,&queue)==VIREO_OK);
    assert(vireo_completion_queue_prepare_wait(queue)==VIREO_OK);
    assert(vireo_notifier_create(&no,&notifier,NULL)==VIREO_OK);
    round_trip("applied",task,&base,VIREO_STATUS_OK,queue,notifier);
    vireo_directory_remove_task_result_t r=base;
    r.service.outcome=VIREO_DIRECTORY_REMOVE_RECOVERED;
    r.service.repository.commit=VIREO_MYSQL_NODE_SOFT_DELETE_NOT_COMMITTED;
    r.service.repository.effect=VIREO_MYSQL_NODE_REMOVE_EFFECT_RECOVERED;
    r.service.repository.rollback_confirmed=true;
    round_trip("recovered",task,&r,VIREO_STATUS_OK,queue,notifier);
    const struct {
        vireo_directory_remove_outcome_t outcome;
        vireo_mysql_node_issue_t issue;
        vireo_result_t rc;
        vireo_status_t status;
    } domains[]={
        {VIREO_DIRECTORY_REMOVE_UNAUTHORIZED,VIREO_MYSQL_NODE_AUTH_REJECTED,VIREO_RESULT_NOT_FOUND,VIREO_STATUS_UNAUTHORIZED},
        {VIREO_DIRECTORY_REMOVE_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND,VIREO_RESULT_NOT_FOUND,VIREO_STATUS_NOT_FOUND},
        {VIREO_DIRECTORY_REMOVE_ROOT_UNDELETABLE,VIREO_MYSQL_NODE_ROOT_UNDELETABLE,VIREO_RESULT_DATABASE,VIREO_STATUS_FORBIDDEN},
        {VIREO_DIRECTORY_REMOVE_DIRECTORY_NOT_EMPTY,VIREO_MYSQL_NODE_DIRECTORY_NOT_EMPTY,VIREO_RESULT_DATABASE,VIREO_STATUS_DIRECTORY_NOT_EMPTY},
        {VIREO_DIRECTORY_REMOVE_OBJECT_REFERENCE_INVALID,VIREO_MYSQL_NODE_OBJECT_REFERENCE_INVALID,VIREO_RESULT_DATABASE,VIREO_STATUS_DB_ERROR},
        {VIREO_DIRECTORY_REMOVE_RECEIPT_INVALID,VIREO_MYSQL_NODE_RECEIPT_INVALID,VIREO_RESULT_DATABASE,VIREO_STATUS_DB_ERROR},
        {VIREO_DIRECTORY_REMOVE_IDEMPOTENCY_CONFLICT,VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT,VIREO_RESULT_DATABASE,VIREO_STATUS_CONFLICT},
        {VIREO_DIRECTORY_REMOVE_ANCESTRY_LIMIT,VIREO_MYSQL_NODE_ANCESTRY_LIMIT,VIREO_RESULT_RANGE,VIREO_STATUS_INTERNAL_ERROR}
    };
    for(size_t i=0;i<sizeof(domains)/sizeof(domains[0]);++i) {
        r=(vireo_directory_remove_task_result_t){.input=base.input,.stage=VIREO_DIRECTORY_REMOVE_TASK_SERVICE,
            .result=domains[i].rc,.service={.outcome=domains[i].outcome,.repository_called=true,
            .repository_result=domains[i].rc,.repository={.issue=domains[i].issue,.rollback_confirmed=true}}};
        round_trip("domain",task,&r,domains[i].status,queue,notifier);
    }
    const struct { vireo_directory_remove_task_stage_t stage; vireo_result_t rc; vireo_status_t status; } gates[]={
        {VIREO_DIRECTORY_REMOVE_TASK_RANDOM,VIREO_RESULT_IO,VIREO_STATUS_INTERNAL_ERROR},
        {VIREO_DIRECTORY_REMOVE_TASK_CANCEL,VIREO_RESULT_CANCELLED,VIREO_STATUS_UNAVAILABLE},
        {VIREO_DIRECTORY_REMOVE_TASK_DEADLINE,VIREO_RESULT_TIMEOUT,VIREO_STATUS_TIMEOUT},
        {VIREO_DIRECTORY_REMOVE_TASK_CONTEXT,VIREO_RESULT_BUSY,VIREO_STATUS_BUSY},
        {VIREO_DIRECTORY_REMOVE_TASK_CONTEXT,VIREO_RESULT_NO_MEMORY,VIREO_STATUS_OVERLOADED}
    };
    for(size_t i=0;i<sizeof(gates)/sizeof(gates[0]);++i) {
        r=(vireo_directory_remove_task_result_t){.input=base.input,.stage=gates[i].stage,.result=gates[i].rc};
        round_trip("gate",task,&r,gates[i].status,queue,notifier);
    }
    /* Unknown commit and historical success with failed cleanup stay technical errors. */
    r=(vireo_directory_remove_task_result_t){.input=base.input,.stage=VIREO_DIRECTORY_REMOVE_TASK_SERVICE,
        .result=VIREO_RESULT_DATABASE,.service={.repository_called=true,.repository_result=VIREO_RESULT_DATABASE,
        .repository={.commit=VIREO_MYSQL_NODE_SOFT_DELETE_UNKNOWN}}};
    round_trip("unknown",task,&r,VIREO_STATUS_DB_ERROR,queue,notifier);
    r=base; r.result=VIREO_RESULT_IO; r.service.outcome=VIREO_DIRECTORY_REMOVE_NONE;
    r.service.node_id=r.service.audit_id=r.service.deleted_at_ms=0;
    memset(r.service.idempotency_key,0,16); r.error.cleanup_result=VIREO_RESULT_IO;
    round_trip("cleanup",task,&r,VIREO_STATUS_INTERNAL_ERROR,queue,notifier);
    for(unsigned mode=0;mode<6;++mode) {
        r=base;
        switch(mode) {
            case 0: ++r.input.request.node_id; break;
            case 1: ++r.input.metadata.deadline_ns; break;
            case 2: r.service.outcome=(vireo_directory_remove_outcome_t)999; break;
            case 3: r.service.repository.effect=VIREO_MYSQL_NODE_REMOVE_EFFECT_NONE; break;
            case 4: r.service.idempotency_key[0]^=1; break;
            default: r.error.database.stage=(vireo_mysql_stage_t)999; break;
        }
        vireo_completion_t *left=NULL; vireo_directory_remove_completion_publish_report_t report;
        assert(vireo_directory_remove_completion_publish(task,404,&r,4096,queue,notifier,&left,&report)!=VIREO_OK);
        assert(!left && !report.publish_called);
    }
    assert(vireo_completion_queue_destroy(&queue)==VIREO_OK);
    assert(vireo_notifier_destroy(&notifier,NULL)==VIREO_OK);
    assert(vireo_task_destroy(&task)==VIREO_OK); return 0;
}
