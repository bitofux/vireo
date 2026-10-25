#include <assert.h>
#include <string.h>
#include "directory_remove_task_internal.h"

static vireo_task_metadata_t meta(void) { return (vireo_task_metadata_t){.route={1,0,3,11},.request_instance_id=9,.operation=404,.deadline_ns=100}; }
static max_align_t repository_storage;
static size_t service_calls;
static vireo_result_t remove_once(void *context, vireo_mysql_node_repository_t *repository,
                                  const vireo_mysql_node_actor_t *actor,
                                  const vireo_mysql_node_remove_once_input_t *input,
                                  uint32_t timeout, vireo_directory_remove_result_t *out,
                                  vireo_mysql_node_error_t *error) {
    (void)context;
    assert(repository == (vireo_mysql_node_repository_t *)(void *)&repository_storage);
    assert(actor->user_id == 7 && actor->session_id == 51 && input->node_id == 123 && timeout == 17);
    assert(input->request_id[0] == 0x31 && input->idempotency_key[0] == 1);
    ++service_calls;
    memset(out, 0, sizeof(*out));
    memset(error, 0, sizeof(*error));
    out->outcome = VIREO_DIRECTORY_REMOVE_APPLIED;
    out->node_id = input->node_id;
    out->audit_id = 8;
    out->deleted_at_ms = 500;
    out->repository_called = true;
    out->repository_result = VIREO_OK;
    out->repository.commit = VIREO_MYSQL_NODE_SOFT_DELETE_COMMITTED;
    out->repository.effect = VIREO_MYSQL_NODE_REMOVE_EFFECT_APPLIED;
    out->repository.node_id = input->node_id;
    out->repository.audit_id = 8;
    out->repository.deleted_at_ms = 500;
    memcpy(out->idempotency_key, input->idempotency_key, 16);
    return VIREO_OK;
}
static void make_wire(unsigned char wire[64]) {
    vireo_node_remove_request_t r={.sequence=11,.session_handle=9,.node_id=123};
    for (size_t i=0;i<16;i++) r.idempotency_key[i]=(unsigned char)(i+1);
    size_t n=0; assert(vireo_node_remove_request_encode(&r,wire,64,&n)==VIREO_OK && n==64);
}
int main(void) {
    unsigned char wire[64]; make_wire(wire); vireo_mysql_node_actor_t actor={7,51};
    vireo_task_t *task=NULL;
    assert(vireo_directory_remove_task_create(meta(),404,wire,64,&actor,4096,NULL,&task)==VIREO_OK);
    vireo_directory_remove_input_t in; vireo_node_remove_issue_t issue;
    assert(vireo_directory_remove_task_read(task,404,&in,&issue)==VIREO_OK);
    assert(in.actor.user_id==7 && in.request.node_id==123 && in.request.sequence==11);
    vireo_directory_remove_task_options_t options={.remove_operation=404,.pool_timeout_ms=17};
    vireo_directory_remove_task_ops_t ops={.context=NULL,.remove=remove_once};
    unsigned char event[16]; memset(event,0x31,sizeof(event));
    vireo_directory_remove_task_result_t result;
    assert(vireo_directory_remove_task_execute_with(task,&options,
           (vireo_mysql_node_repository_t *)(void *)&repository_storage,event,100,&result,&ops)==VIREO_RESULT_TIMEOUT);
    assert(result.stage==VIREO_DIRECTORY_REMOVE_TASK_DEADLINE && service_calls==0);
    assert(vireo_directory_remove_task_execute_with(task,&options,
           (vireo_mysql_node_repository_t *)(void *)&repository_storage,event,99,&result,&ops)==VIREO_OK);
    assert(result.stage==VIREO_DIRECTORY_REMOVE_TASK_SERVICE && service_calls==1 &&
           result.service.deleted_at_ms==500 && !memcmp(result.service.idempotency_key,in.request.idempotency_key,16));
    vireo_task_cancel_t *cancel=NULL;
    assert(vireo_task_cancel_create(4096,&cancel)==VIREO_OK);
    vireo_task_t *cancelled_task=NULL;
    assert(vireo_directory_remove_task_create(meta(),404,wire,64,&actor,4096,cancel,&cancelled_task)==VIREO_OK);
    assert(vireo_task_cancel_request(cancel)==VIREO_OK);
    assert(vireo_directory_remove_task_execute_with(cancelled_task,&options,
           (vireo_mysql_node_repository_t *)(void *)&repository_storage,event,99,&result,&ops)==VIREO_RESULT_CANCELLED);
    assert(result.stage==VIREO_DIRECTORY_REMOVE_TASK_CANCEL && service_calls==1);
    assert(vireo_task_destroy(&cancelled_task)==VIREO_OK);
    assert(vireo_task_cancel_destroy(&cancel)==VIREO_OK);
    unsigned char bad[64]; memcpy(bad,wire,64); bad[0]^=1;
    vireo_task_t *bad_task=NULL;
    assert(vireo_directory_remove_task_create(meta(),404,bad,64,&actor,4096,NULL,&bad_task)==VIREO_RESULT_PROTOCOL);
    assert(!bad_task); assert(vireo_task_destroy(&task)==VIREO_OK);
    return 0;
}
