#include "directory_stat_test_support.h"
#include "directory_stat_test_vectors.h"
#include "directory_stat_completion_internal.h"
#include <pthread.h>
static vireo_completion_t *copy(const unsigned char *bytes,size_t size,vireo_result_t rc,vireo_status_t status,vireo_task_metadata_t m)
{
    vireo_completion_metadata_t cm;CHECK(vireo_completion_metadata_make(m,rc,status,&cm),VIREO_OK);
    vireo_completion_t *c=NULL;CHECK(vireo_completion_create_copy(cm,bytes,size,4096,&c),VIREO_OK);return c;
}
static void decode_check(vireo_completion_t **c,bool valid)
{
    vireo_directory_stat_completion_outcome_t out,old;memset(&out,0xa5,sizeof(out));memcpy(&old,&out,sizeof(out));
    CHECK(vireo_directory_stat_completion_decode(*c,400,&out),valid?VIREO_OK:VIREO_RESULT_PROTOCOL);
    if(!valid)assert(!memcmp(&out,&old,sizeof(out)));
    else assert(out.actor.user_id && out.actor.session_id && out.requested_node_id && out.request_session_handle);
    CHECK(vireo_completion_destroy(c),VIREO_OK);
}
static void vectors(void)
{
    for(size_t i=0;i<sizeof(goldens)/sizeof(goldens[0]);++i) {
        const golden_t *g=&goldens[i];if(g->task)continue;
        const vireo_status_t status=(vireo_status_t)(((unsigned)g->bytes[50]<<8)|g->bytes[51]);
        vireo_completion_t *c=copy(g->bytes,g->size,g->result,status,metadata());decode_check(&c,g->valid);
    }
    const golden_t *g=NULL;
    for(size_t i=0;i<sizeof(goldens)/sizeof(goldens[0]);++i)if(!strcmp(goldens[i].name,"completion_root"))g=&goldens[i];
    assert(g && g->size==130);
    unsigned char bytes[434]={0};memcpy(bytes,g->bytes,g->size);
    for(size_t n=0;n<=434;++n) {
        if(n==g->size)continue;
        vireo_completion_t *c=copy(bytes,n,VIREO_OK,VIREO_STATUS_OK,metadata());decode_check(&c,false);
    }
    for(unsigned i=0;i<10;++i) {
        memcpy(bytes,g->bytes,g->size);vireo_task_metadata_t m=metadata();
        switch(i) {
        case 0:memset(bytes+8,0,8);break;case 1:memset(bytes+16,0,8);break;
        case 2:memset(bytes+24,0,8);break;case 3:memset(bytes+32,0,4);break;
        case 4:put32_test(bytes+36,0);break;case 5:bytes[68]^=1;break;
        case 6:m.operation=401;break;case 7:++m.route.request_sequence;break;
        case 8:bytes[83]=0;crc_fix(bytes+40,90);break; /* 合法CRC，节点0仍拒绝。 */
        default:bytes[4]=1;break;
        }
        vireo_completion_t *c=copy(bytes,g->size,VIREO_OK,VIREO_STATUS_OK,m);decode_check(&c,false);
    }
    const vireo_status_t statuses[]={VIREO_STATUS_OK,VIREO_STATUS_BAD_REQUEST,VIREO_STATUS_UNSUPPORTED,
        VIREO_STATUS_CRC_MISMATCH,VIREO_STATUS_BODY_TOO_LARGE,VIREO_STATUS_INVALID_FLAGS,VIREO_STATUS_DUPLICATE_REQUEST,
        VIREO_STATUS_RATE_LIMITED,VIREO_STATUS_UNAUTHORIZED,VIREO_STATUS_NOT_FOUND,VIREO_STATUS_BUSY,
        VIREO_STATUS_INTERNAL_ERROR,VIREO_STATUS_TIMEOUT,VIREO_STATUS_OVERLOADED,VIREO_STATUS_UNAVAILABLE};
    for(int rc=0;rc<=12;++rc)for(size_t j=0;j<sizeof(statuses)/sizeof(statuses[0]);++j) {
        vireo_node_stat_response_t response={.status=statuses[j],.sequence=1};size_t size=0;
        memcpy(bytes,g->bytes,40);
        if(!statuses[j]) {memcpy(bytes+40,g->bytes+40,90);size=90;}
        else CHECK(vireo_node_stat_response_encode(&response,bytes+40,393,&size),VIREO_OK);
        put32_test(bytes+36,(uint32_t)size);
        bool valid=rc==0?statuses[j]==VIREO_STATUS_OK:rc==5?(statuses[j]==VIREO_STATUS_UNAUTHORIZED || statuses[j]==VIREO_STATUS_NOT_FOUND):
            statuses[j]==VIREO_STATUS_INTERNAL_ERROR || (rc==6 && statuses[j]==VIREO_STATUS_BUSY) ||
            (rc==7 && statuses[j]==VIREO_STATUS_TIMEOUT) || (rc==8 && statuses[j]==VIREO_STATUS_UNAVAILABLE);
        vireo_completion_t *c=copy(bytes,40+size,(vireo_result_t)rc,statuses[j],metadata());decode_check(&c,valid);
    }
}
static vireo_status_t publish_decode(vireo_task_t *task,vireo_directory_stat_task_result_t *r,
    vireo_completion_queue_t *q,vireo_notifier_t *n)
{
    vireo_completion_t *left=NULL;vireo_directory_stat_completion_publish_report_t p;
    CHECK(vireo_directory_stat_completion_publish(task,400,r,4096,q,n,&left,&p),VIREO_OK);
    assert(!left && p.task_matched && p.result_validated && p.publish_called && p.publication.completion_transferred);
    vireo_completion_t *c=pop(q);
    if(r->result==VIREO_OK && !r->service.node.has_parent) {
        vireo_completion_payload_view_t view;CHECK(vireo_completion_borrow_payload(c,&view),VIREO_OK);
        const golden_t *gold=NULL;
        for(size_t k=0;k<sizeof(goldens)/sizeof(goldens[0]);++k)if(!strcmp(goldens[k].name,"completion_root"))gold=&goldens[k];
        assert(gold && view.size==gold->size && !memcmp(view.data,gold->bytes,view.size));
    }
    vireo_directory_stat_completion_outcome_t out;
    CHECK(vireo_directory_stat_completion_decode(c,400,&out),VIREO_OK);
    assert(out.metadata.result==r->result && out.response.sequence==1 && out.requested_node_id==42 && out.request_session_handle==2);
    if(out.response.status!=VIREO_STATUS_OK)assert(!out.response.session_handle && !out.response.metadata.node_id);
    CHECK(vireo_completion_destroy(&c),VIREO_OK);return out.response.status;
}
static void projection(void)
{
    vireo_completion_queue_t *q=NULL;vireo_notifier_t *n=NULL;queue_setup(&q,&n,true);
    vireo_task_t *t=make_task(42,100,NULL);vireo_directory_stat_task_result_t r=found_result(t);
    assert(publish_decode(t,&r,q,n)==VIREO_STATUS_OK);
    vireo_completion_t *left=NULL;vireo_directory_stat_completion_publish_report_t p;
    for(unsigned i=0;i<20;++i) {
        r=found_result(t);vireo_result_t want=VIREO_RESULT_INVALID_ARGUMENT;
        switch(i) {
        case 0:++r.input.metadata.route.client_owner_id;want=VIREO_RESULT_PROTOCOL;break;
        case 1:++r.input.metadata.route.client_slot_index;want=VIREO_RESULT_PROTOCOL;break;
        case 2:++r.input.metadata.route.client_generation;want=VIREO_RESULT_PROTOCOL;break;
        case 3:++r.input.metadata.route.request_sequence;want=VIREO_RESULT_PROTOCOL;break;
        case 4:++r.input.metadata.request_instance_id;want=VIREO_RESULT_PROTOCOL;break;
        case 5:++r.input.metadata.operation;want=VIREO_RESULT_PROTOCOL;break;
        case 6:++r.input.metadata.deadline_ns;want=VIREO_RESULT_PROTOCOL;break;
        case 7:++r.input.actor.user_id;want=VIREO_RESULT_PROTOCOL;break;
        case 8:++r.input.actor.session_id;want=VIREO_RESULT_PROTOCOL;break;
        case 9:++r.input.request.node_id;want=VIREO_RESULT_PROTOCOL;break;
        case 10:++r.input.request.session_handle;want=VIREO_RESULT_PROTOCOL;break;
        case 11:++r.service.node.owner_id;break;case 12:r.service.repository.rollback_confirmed=false;break;
        case 13:r.service.repository.cleanup_pending=true;break;case 14:r.error.cleanup_result=VIREO_RESULT_IO;break;
        case 15:r.service.node.name_length=256;break;case 16:r.result=(vireo_result_t)13;break;
        case 17:r.stage=VIREO_DIRECTORY_STAT_TASK_CONTEXT;break;case 18:r.service.repository.found=false;break;
        default:r.service.node.kind=(vireo_mysql_node_kind_t)65537;break;
        }
        CHECK(vireo_directory_stat_completion_publish(t,400,&r,4096,q,n,&left,&p),want);assert(!left && !p.publish_called);empty(q);
    }
    for(unsigned i=0;i<2;++i) {
        r=found_result(t);r.result=VIREO_RESULT_NOT_FOUND;
        r.service=(vireo_directory_stat_result_t){.outcome=i?VIREO_DIRECTORY_STAT_NOT_FOUND:VIREO_DIRECTORY_STAT_UNAUTHORIZED,
            .repository_called=true,.repository_result=VIREO_RESULT_NOT_FOUND,
            .repository={.rollback_confirmed=true,.issue=i?VIREO_MYSQL_NODE_NOT_FOUND:VIREO_MYSQL_NODE_AUTH_REJECTED}};
        assert(publish_decode(t,&r,q,n)==(i?VIREO_STATUS_NOT_FOUND:VIREO_STATUS_UNAUTHORIZED));
    }
    for(int rc=1;rc<=12;++rc) {
        if(rc==5)continue;
        r=found_result(t);r.result=(vireo_result_t)rc;r.stage=VIREO_DIRECTORY_STAT_TASK_CONTEXT;
        r.service=(vireo_directory_stat_result_t){0};
        assert(publish_decode(t,&r,q,n)==(rc==6?VIREO_STATUS_BUSY:rc==7?VIREO_STATUS_TIMEOUT:rc==8?VIREO_STATUS_UNAVAILABLE:VIREO_STATUS_INTERNAL_ERROR));
        r.stage=VIREO_DIRECTORY_STAT_TASK_SERVICE;r.service.repository_called=true;r.service.repository_result=(vireo_result_t)rc;
        r.service.repository.cleanup_pending=true;
        assert(publish_decode(t,&r,q,n)==VIREO_STATUS_INTERNAL_ERROR);
        r.service.repository.cleanup_pending=false;r.error.cleanup_result=VIREO_RESULT_IO;
        assert(publish_decode(t,&r,q,n)==VIREO_STATUS_INTERNAL_ERROR);
    }
    r=found_result(t);CHECK(vireo_directory_stat_completion_publish(t,400,&r,1,q,n,&left,&p),VIREO_RESULT_RANGE);assert(!left && !p.publication.completion_created);
    vireo_completion_queue_close_report_t close;CHECK(vireo_completion_queue_close(q,&close),VIREO_OK);
    CHECK(vireo_directory_stat_completion_publish(t,400,&r,4096,q,n,&left,&p),VIREO_RESULT_CANCELLED);
    assert(left && p.publication.completion_retained && !p.publication.completion_transferred);
    CHECK(vireo_task_destroy(&t),VIREO_OK);memset(&r,0,sizeof(r));decode_check(&left,true);queue_teardown(&q,&n);
    queue_setup(&q,&n,false);t=make_task(42,100,NULL);r=found_result(t);
    CHECK(vireo_directory_stat_completion_publish(t,400,&r,4096,q,n,&left,&p),VIREO_RESULT_NOT_FOUND);assert(left);
    CHECK(vireo_completion_destroy(&left),VIREO_OK);CHECK(vireo_task_destroy(&t),VIREO_OK);queue_teardown(&q,&n);
}
/* 注入公开publisher在真实转交后报告通知故障，验证上层保留已交接事实。 */
static vireo_result_t notify_fail(const vireo_task_t *t,vireo_result_t rc,vireo_status_t status,const void *data,size_t size,
    size_t budget,vireo_completion_queue_t *q,vireo_notifier_t *n,vireo_completion_t **left,vireo_completion_publish_report_t *p)
{
    vireo_result_t got=vireo_completion_copy_wait_publish(t,rc,status,data,size,budget,q,n,left,p);assert(got==VIREO_OK);
    p->notify_result=VIREO_RESULT_IO;p->stage=VIREO_COMPLETION_PUBLISH_NOTIFY;errno=EIO;return VIREO_RESULT_IO;
}
static void transfer(void)
{
    vireo_completion_queue_t *q=NULL;vireo_notifier_t *n=NULL;queue_setup(&q,&n,true);
    vireo_task_t *t=make_task(42,100,NULL);vireo_directory_stat_task_result_t r=found_result(t);
    vireo_completion_t *left=NULL;vireo_directory_stat_completion_publish_report_t p;
    CHECK(vireo_directory_stat_completion_publish_with(t,400,&r,4096,q,n,&left,&p,notify_fail),VIREO_RESULT_IO);
    assert(!left && p.publication.completion_transferred && !p.publication.completion_retained);
    CHECK(vireo_task_destroy(&t),VIREO_OK);memset(&r,0,sizeof(r));vireo_completion_t *c=pop(q);decode_check(&c,true);queue_teardown(&q,&n);
}
/* 队列已满后启动producer，consumer腾空间后再join，不依赖固定sleep。 */
typedef struct producer {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool entered;
    vireo_task_t *task;
    vireo_directory_stat_task_result_t result;
    vireo_completion_queue_t *queue;
    vireo_notifier_t *notifier;
} producer_t;
static void *produce(void *context)
{
    producer_t *p=context;int old=0;assert(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old));
    assert(!pthread_mutex_lock(&p->mutex));p->entered=true;assert(!pthread_cond_signal(&p->cond));assert(!pthread_mutex_unlock(&p->mutex));
    vireo_completion_t *left=NULL;vireo_directory_stat_completion_publish_report_t report;
    CHECK(vireo_directory_stat_completion_publish(p->task,400,&p->result,4096,p->queue,p->notifier,&left,&report),VIREO_OK);
    assert(!left && report.publication.completion_transferred);return NULL;
}
static vireo_result_t no_memory(const vireo_task_t *t,vireo_result_t rc,vireo_status_t status,const void *data,size_t size,
    size_t budget,vireo_completion_queue_t *q,vireo_notifier_t *n,vireo_completion_t **left,vireo_completion_publish_report_t *p)
{
    (void)t;(void)rc;(void)status;(void)data;(void)size;(void)budget;(void)q;(void)n;assert(!*left);
    p->stage=VIREO_COMPLETION_PUBLISH_CREATE_COMPLETION;errno=ENOMEM;return VIREO_RESULT_NO_MEMORY;
}
static void pressure(void)
{
    producer_t p={.mutex=PTHREAD_MUTEX_INITIALIZER,.cond=PTHREAD_COND_INITIALIZER};
    queue_setup(&p.queue,&p.notifier,true);p.task=make_task(42,100,NULL);p.result=found_result(p.task);
    vireo_completion_t *left=NULL;vireo_directory_stat_completion_publish_report_t report;
    CHECK(vireo_directory_stat_completion_publish_with(p.task,400,&p.result,4096,p.queue,p.notifier,&left,&report,no_memory),VIREO_RESULT_NO_MEMORY);
    assert(!left && report.result_validated && report.publish_called && !report.publication.completion_created);empty(p.queue);
    const golden_t *g=NULL;for(size_t i=0;i<sizeof(goldens)/sizeof(goldens[0]);++i)if(!strcmp(goldens[i].name,"completion_root"))g=&goldens[i];assert(g);
    vireo_task_metadata_t md=metadata();md.request_instance_id=8;
    vireo_completion_t *first=copy(g->bytes,g->size,VIREO_OK,VIREO_STATUS_OK,md);vireo_completion_queue_transfer_report_t moved;
    CHECK(vireo_completion_queue_try_push(p.queue,&first,&moved),VIREO_OK);assert(!first && moved.transferred);
    pthread_t thread;assert(!pthread_create(&thread,NULL,produce,&p));
    assert(!pthread_mutex_lock(&p.mutex));while(!p.entered)assert(!pthread_cond_wait(&p.cond,&p.mutex));assert(!pthread_mutex_unlock(&p.mutex));
    vireo_result_t rc;do {rc=vireo_completion_queue_try_pop(p.queue,&first,&moved);}while(rc==VIREO_RESULT_BUSY);
    assert(rc==VIREO_OK && first && moved.transferred);CHECK(vireo_completion_destroy(&first),VIREO_OK);
    assert(!pthread_join(thread,NULL));vireo_completion_t *c=pop(p.queue);decode_check(&c,true);
    CHECK(vireo_task_destroy(&p.task),VIREO_OK);queue_teardown(&p.queue,&p.notifier);
    assert(!pthread_cond_destroy(&p.cond));assert(!pthread_mutex_destroy(&p.mutex));
}
int main(void)
{ int old_state=0;assert(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old_state));vectors();projection();transfer();pressure();printf("PASS directory_stat_completion: %zu boundary calls; fixed VDC1 vectors, 195 rc/status pairs, malformed lengths/schema, all metadata associations, cleanup precedence and transfer ownership\n",checks);return 0;}
