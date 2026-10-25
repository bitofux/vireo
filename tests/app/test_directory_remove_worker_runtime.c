#define _POSIX_C_SOURCE 200809L
#include "directory_remove_worker_runtime_internal.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct model { unsigned create_calls,run_calls,destroy_calls,previous_calls; bool fail_create; max_align_t owner; } model_t;
static vireo_directory_remove_worker_t *owner(model_t *m)
{ return (vireo_directory_remove_worker_t *)&m->owner; }
static vireo_result_t create(void *context,vireo_directory_remove_worker_resources_t const *r,
    vireo_directory_remove_worker_options_t const *o,vireo_directory_remove_worker_t **out)
{
    model_t *m=context; assert(r && o && !*out); ++m->create_calls;
    if(m->fail_create) return VIREO_RESULT_NO_MEMORY;
    *out=owner(m); return VIREO_OK;
}
static vireo_result_t run(void *context,vireo_directory_remove_worker_t *w,const vireo_task_t *t,
    vireo_directory_remove_worker_report_t *out)
{
    model_t *m=context; assert(w==owner(m) && t); ++m->run_calls;
    *out=(vireo_directory_remove_worker_report_t){.task_validated=true,.publish_called=true,.publish_result=VIREO_OK};
    out->publication.publication.completion_transferred=true; return VIREO_OK;
}
static vireo_result_t destroy(void *context,vireo_directory_remove_worker_t **w,
    vireo_directory_remove_worker_cleanup_report_t *out)
{ model_t *m=context; assert(*w==owner(m)); ++m->destroy_calls; *w=NULL; *out=(vireo_directory_remove_worker_cleanup_report_t){0}; return VIREO_OK; }
static vireo_result_t previous(void *context,vireo_directory_move_worker_runtime_t *r,const vireo_task_t *t)
{ model_t *m=context; assert(r && t); ++m->previous_calls; return VIREO_OK; }
static vireo_directory_remove_worker_runtime_ops_t ops(model_t *m)
{ return (vireo_directory_remove_worker_runtime_ops_t){m,create,run,destroy,previous}; }

static void setup(vireo_directory_remove_worker_runtime_t *remove,vireo_directory_move_worker_runtime_t *move)
{
    static max_align_t marker[8]; static vireo_auth_worker_runtime_t auth;
    static vireo_directory_stat_worker_runtime_t stat; static vireo_directory_root_worker_runtime_t root;
    static vireo_directory_list_worker_runtime_t list; static vireo_directory_mkdir_worker_runtime_t mkdir;
    vireo_auth_worker_resources_t const ar={(void *)&marker[0],(void *)&marker[0],(void *)&marker[0],
        (void *)&marker[0],(void *)&marker[0],(void *)&marker[0],NULL};
    vireo_auth_worker_options_t const ao={.execution={100,101,5000,102,103},.password=VIREO_PASSWORD_POLICY_DEFAULT,
        .request_timeout_ns=10,.session_lifetime_ms=60000,.completion_allocation_budget=4096,.max_memory_bytes=65536};
    assert(vireo_auth_worker_runtime_init(&auth,&ar,&ao,3)==VIREO_OK);
    vireo_directory_stat_worker_resources_t const sr={ar.runtime,ar.database,(void *)&marker[1],ar.notifier};
    vireo_directory_stat_worker_options_t const so={.execution={104,5000},.completion_allocation_budget=4096,.max_memory_bytes=65536};
    assert(vireo_directory_stat_worker_runtime_init(&stat,&auth,&sr,&so,3)==VIREO_OK);
    vireo_directory_root_worker_resources_t const rr={ar.runtime,ar.database,(void *)&marker[2],ar.notifier};
    vireo_directory_root_worker_options_t const ro={.execution={105,5000},.completion_allocation_budget=4096,.max_memory_bytes=65536};
    assert(vireo_directory_root_worker_runtime_init(&root,&stat,&rr,&ro,3)==VIREO_OK);
    vireo_directory_list_worker_resources_t const lr={ar.runtime,(void *)&marker[3],ar.database,(void *)&marker[4],ar.notifier};
    vireo_directory_list_worker_options_t const lo={.execution={106,5000},.completion_allocation_budget=32768,.max_memory_bytes=65536};
    assert(vireo_directory_list_worker_runtime_init(&list,&root,&lr,&lo,3)==VIREO_OK);
    vireo_directory_mkdir_worker_resources_t const kr={ar.runtime,ar.database,(void *)&marker[5],ar.notifier};
    vireo_directory_mkdir_worker_options_t const ko={.execution={107,5000},.completion_allocation_budget=4096,.max_memory_bytes=65536};
    assert(vireo_directory_mkdir_worker_runtime_init(&mkdir,&list,&kr,&ko,3)==VIREO_OK);
    vireo_directory_move_worker_resources_t const mr={ar.runtime,ar.database,(void *)&marker[6],ar.notifier};
    vireo_directory_move_worker_options_t const mo={.execution={108,5000},.completion_allocation_budget=4096,.max_memory_bytes=65536};
    assert(vireo_directory_move_worker_runtime_init(move,&mkdir,&mr,&mo,3)==VIREO_OK);
    vireo_directory_remove_worker_resources_t const xr={ar.runtime,ar.database,(void *)&marker[7],ar.notifier};
    vireo_directory_remove_worker_options_t const xo={.execution={109,5000},.completion_allocation_budget=4096,.max_memory_bytes=65536};
    assert(vireo_directory_remove_worker_runtime_init(remove,move,&xr,&xo,3)==VIREO_OK);
}
static vireo_task_t *task(uint32_t operation)
{
    vireo_task_metadata_t metadata={.route={1,0,1,1},.request_instance_id=1,.operation=operation,.deadline_ns=10};
    vireo_task_t *out=NULL; assert(vireo_task_create_copy(metadata,"x",1,4096,&out)==VIREO_OK); return out;
}
static unsigned remove_fault(vireo_directory_remove_worker_runtime_t const *r)
{ vireo_directory_remove_worker_faults_t f={0}; assert(vireo_directory_remove_worker_runtime_inspect_faults(r,&f)==VIREO_OK); return f.remove; }
int main(void)
{
    vireo_directory_remove_worker_runtime_t runtime; vireo_directory_move_worker_runtime_t move; setup(&runtime,&move);
    model_t m={0}; vireo_directory_remove_worker_runtime_ops_t callbacks=ops(&m);
    vireo_task_t *t=task(109);
    assert(vireo_directory_remove_worker_runtime_execute_with(&runtime,t,&callbacks)==VIREO_OK);
    assert(m.create_calls==1 && m.run_calls==1 && m.destroy_calls==1 && !m.previous_calls && remove_fault(&runtime)==0);
    assert(vireo_task_destroy(&t)==VIREO_OK);
    t=task(108); assert(vireo_directory_remove_worker_runtime_execute_with(&runtime,t,&callbacks)==VIREO_OK);
    assert(m.previous_calls==1 && m.create_calls==1 && remove_fault(&runtime)==0); assert(vireo_task_destroy(&t)==VIREO_OK);
    t=task(999); assert(vireo_directory_remove_worker_runtime_execute_with(&runtime,t,&callbacks)==VIREO_RESULT_NOT_FOUND);
    assert(m.previous_calls==1 && remove_fault(&runtime)==0); assert(vireo_task_destroy(&t)==VIREO_OK);
    m.fail_create=true; t=task(109);
    assert(vireo_directory_remove_worker_runtime_execute_with(&runtime,t,&callbacks)==VIREO_RESULT_NO_MEMORY);
    assert(remove_fault(&runtime)==VIREO_DIRECTORY_REMOVE_WORKER_FAULT_CREATE);
    assert(vireo_directory_remove_worker_runtime_execute_with(&runtime,t,&callbacks)==VIREO_RESULT_CANCELLED);
    assert(m.create_calls==2 && m.run_calls==1 && m.destroy_calls==1); assert(vireo_task_destroy(&t)==VIREO_OK);
    puts("PASS directory_remove_worker_runtime: operation 109, prior operation delegation, unknown tag isolation, permanent CREATE fault latch");
    return 0;
}
