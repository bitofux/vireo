#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vireo/persistence/mysql_schema.h>
#include <vireo/persistence/mysql_user_repository.h>
#include <vireo/service/directory_remove_worker.h>
#include <vireo/thread/completion_queue.h>
#include <vireo/thread/notifier.h>

#define CHECK(call) do { vireo_result_t rc=(call); if(rc!=VIREO_OK){fprintf(stderr,"line %d rc=%d\n",__LINE__,(int)rc);abort();} } while(0)
typedef struct remove_worker_job {
 vireo_directory_remove_worker_resources_t resources;
 vireo_directory_remove_worker_options_t options;
 vireo_task_t *task;
 vireo_directory_remove_worker_report_t report;
 vireo_directory_remove_worker_cleanup_report_t cleanup;
 vireo_result_t create_result;
 vireo_result_t run_result;
 vireo_result_t destroy_result;
} remove_worker_job_t;
static void *run_remove_worker(void *context){
 remove_worker_job_t *job=context; vireo_directory_remove_worker_t *worker=NULL;
 int previous_cancel_state=0;assert(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&previous_cancel_state)==0);
 job->create_result=vireo_directory_remove_worker_create(&job->resources,&job->options,&worker);
 if(job->create_result==VIREO_OK){job->run_result=vireo_directory_remove_worker_run(worker,job->task,&job->report);job->destroy_result=vireo_directory_remove_worker_destroy(&worker,&job->cleanup);}
 else {job->run_result=job->create_result;job->destroy_result=job->create_result;}
 assert(worker==NULL); return NULL;
}
static remove_worker_job_t make_job(vireo_directory_remove_worker_resources_t resources,
                                   vireo_mysql_node_actor_t actor,uint64_t node,unsigned char key){
 vireo_node_remove_request_t request={.sequence=17,.session_handle=19,.node_id=node,.idempotency_key={0}};
 request.idempotency_key[0]=key;unsigned char wire[64];size_t size=0;
 CHECK(vireo_node_remove_request_encode(&request,wire,sizeof(wire),&size));
 vireo_task_metadata_t metadata={.route={1,0,1,17},.request_instance_id=23,.operation=404,.deadline_ns=UINT64_MAX};
 remove_worker_job_t job={.resources=resources,.options={.execution={404,1000},.completion_allocation_budget=4096,.max_memory_bytes=65536}};
 CHECK(vireo_directory_remove_task_create(metadata,404,wire,size,&actor,4096,NULL,&job.task));return job;
}
static void join_job(remove_worker_job_t *job,vireo_result_t expected){
 pthread_t worker_thread;assert(pthread_create(&worker_thread,NULL,run_remove_worker,job)==0);
 assert(pthread_join(worker_thread,NULL)==0);CHECK(job->create_result);assert(job->run_result==expected);CHECK(job->destroy_result);
 assert(job->report.publish_called&&job->report.publication.publication.completion_transferred&&!job->report.publication_blocked_by_cleanup);
}
static void consume(vireo_completion_queue_t *queue,vireo_status_t status,uint64_t node){
 vireo_completion_t *completion=NULL;vireo_completion_queue_transfer_report_t transfer;
 CHECK(vireo_completion_queue_try_pop(queue,&completion,&transfer));
 vireo_directory_remove_completion_outcome_t outcome;CHECK(vireo_directory_remove_completion_decode(completion,404,&outcome));
 assert(outcome.response.status==status&&outcome.request_node_id==node);
 if(status==VIREO_STATUS_OK)assert(outcome.response.node_id==node);
 CHECK(vireo_completion_destroy(&completion));
}
int main(int argc,char **argv){
 assert(argc==5); char password[1024]; FILE*f=fopen(argv[3],"r");assert(f&&fgets(password,sizeof(password),f));assert(fclose(f)==0);password[strcspn(password,"\n")]=0;
 struct sigaction sa={0};sa.sa_handler=SIG_IGN;assert(sigemptyset(&sa.sa_mask)==0&&sigaction(SIGPIPE,&sa,NULL)==0);
 vireo_mysql_runtime_t*runtime=NULL;vireo_mysql_thread_t*thread=NULL;vireo_mysql_pool_t*pool=NULL;vireo_mysql_connection_t*connection_handle=NULL;vireo_mysql_user_repository_t*users=NULL;vireo_mysql_node_repository_t*nodes=NULL;
 CHECK(vireo_mysql_runtime_create(&runtime,NULL));CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL));
 vireo_mysql_connection_options_t connection={argv[1],argv[2],password,argv[4],3,3,3};const vireo_mysql_migration_t*catalog=NULL;size_t count=0;CHECK(vireo_mysql_schema_catalog(&catalog,&count));vireo_mysql_migration_report_t migration;CHECK(vireo_mysql_migration_apply(thread,&connection,catalog,count,&migration,NULL));
 CHECK(vireo_mysql_connection_open(thread,&connection,&connection_handle,NULL));vireo_mysql_pool_options_t po={connection,3,3,VIREO_MYSQL_POOL_MEMORY_MAX};CHECK(vireo_mysql_pool_create(thread,&po,&pool,NULL));
 const vireo_password_policy_t policy=VIREO_PASSWORD_POLICY_DEFAULT;CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&users,NULL));CHECK(vireo_mysql_node_repository_create(thread,pool,&nodes,NULL));
 char phc[VIREO_PASSWORD_ENCODED_CAPACITY];size_t phc_size=0;CHECK(vireo_password_hash_create(&policy,"Correct!7",9,phc,sizeof(phc),&phc_size));struct timespec now;assert(clock_gettime(CLOCK_REALTIME,&now)==0);uint64_t ms=(uint64_t)now.tv_sec*1000+(uint64_t)now.tv_nsec/1000000;
 vireo_mysql_registration_input_t registration={.username="remove_worker",.username_length=13,.username_key="remove_worker",.username_key_length=13,.password_hash=phc,.password_hash_length=phc_size,.occurred_at_ms=ms-1000,.request_id={1}};vireo_mysql_registration_report_t registered;CHECK(vireo_mysql_user_repository_register(users,&registration,0,&registered,NULL));
 vireo_mysql_login_input_t login={.user_id=registered.user_id,.verified_password_hash=phc,.verified_password_hash_length=phc_size,.issued_at_ms=ms,.expires_at_ms=ms+3600000,.request_id={2},.token_digest={.bytes={3}}};vireo_mysql_login_report_t logged;CHECK(vireo_mysql_user_repository_login(users,&login,0,&logged,NULL));vireo_mysql_node_actor_t actor={registered.user_id,logged.session_id};
 vireo_mysql_node_mkdir_input_t mkdir={.parent_id=registered.root_node_id,.name=(const unsigned char*)"worker-target",.name_length=13,.request_id={4}};vireo_mysql_node_mkdir_report_t node;CHECK(vireo_mysql_node_repository_mkdir(nodes,&actor,&mkdir,0,&node,NULL));
 vireo_completion_queue_options_t qo={2,65536};vireo_completion_queue_t*queue=NULL;vireo_notifier_t*notifier=NULL;vireo_notifier_options_t no={4096};CHECK(vireo_completion_queue_create(&qo,&queue));CHECK(vireo_completion_queue_prepare_wait(queue));CHECK(vireo_notifier_create(&no,&notifier,NULL));
 vireo_directory_remove_worker_resources_t resources={runtime,pool,queue,notifier};
 remove_worker_job_t job=make_job(resources,actor,node.node.id,5);join_job(&job,VIREO_OK);
 assert(job.report.service.outcome==VIREO_DIRECTORY_REMOVE_APPLIED);uint64_t audit=job.report.service.audit_id;
 consume(queue,VIREO_STATUS_OK,node.node.id);CHECK(vireo_task_destroy(&job.task));
 job=make_job(resources,actor,node.node.id,5);join_job(&job,VIREO_OK);
 assert(job.report.service.outcome==VIREO_DIRECTORY_REMOVE_RECOVERED&&job.report.service.audit_id==audit);
 consume(queue,VIREO_STATUS_OK,node.node.id);CHECK(vireo_task_destroy(&job.task));
 job=make_job(resources,actor,registered.root_node_id,5);join_job(&job,VIREO_RESULT_DATABASE);
 assert(job.report.service.outcome==VIREO_DIRECTORY_REMOVE_IDEMPOTENCY_CONFLICT);
 consume(queue,VIREO_STATUS_CONFLICT,registered.root_node_id);CHECK(vireo_task_destroy(&job.task));
 job=make_job(resources,actor,registered.root_node_id,6);join_job(&job,VIREO_RESULT_DATABASE);
 assert(job.report.service.outcome==VIREO_DIRECTORY_REMOVE_ROOT_UNDELETABLE);
 consume(queue,VIREO_STATUS_FORBIDDEN,registered.root_node_id);CHECK(vireo_task_destroy(&job.task));
 mkdir.name=(const unsigned char *)"parent";mkdir.name_length=6;mkdir.request_id[0]=7;
 vireo_mysql_node_mkdir_report_t parent,child;CHECK(vireo_mysql_node_repository_mkdir(nodes,&actor,&mkdir,0,&parent,NULL));
 mkdir.parent_id=parent.node.id;mkdir.name=(const unsigned char *)"child";mkdir.name_length=5;mkdir.request_id[0]=8;
 CHECK(vireo_mysql_node_repository_mkdir(nodes,&actor,&mkdir,0,&child,NULL));
 job=make_job(resources,actor,parent.node.id,9);join_job(&job,VIREO_RESULT_DATABASE);
 assert(job.report.service.outcome==VIREO_DIRECTORY_REMOVE_DIRECTORY_NOT_EMPTY);
 consume(queue,VIREO_STATUS_DIRECTORY_NOT_EMPTY,parent.node.id);CHECK(vireo_task_destroy(&job.task));
 remove_worker_job_t concurrent[2]={make_job(resources,actor,child.node.id,10),make_job(resources,actor,child.node.id,10)};
 pthread_t workers[2];for(size_t i=0;i<2;++i)assert(pthread_create(&workers[i],NULL,run_remove_worker,&concurrent[i])==0);
 for(size_t i=0;i<2;++i){assert(pthread_join(workers[i],NULL)==0);CHECK(concurrent[i].create_result);CHECK(concurrent[i].run_result);CHECK(concurrent[i].destroy_result);consume(queue,VIREO_STATUS_OK,child.node.id);CHECK(vireo_task_destroy(&concurrent[i].task));}
 assert(concurrent[0].report.service.audit_id==concurrent[1].report.service.audit_id);
 assert((concurrent[0].report.service.outcome==VIREO_DIRECTORY_REMOVE_APPLIED&&concurrent[1].report.service.outcome==VIREO_DIRECTORY_REMOVE_RECOVERED)||(concurrent[1].report.service.outcome==VIREO_DIRECTORY_REMOVE_APPLIED&&concurrent[0].report.service.outcome==VIREO_DIRECTORY_REMOVE_RECOVERED));
 CHECK(vireo_completion_queue_destroy(&queue));CHECK(vireo_notifier_destroy(&notifier,NULL));CHECK(vireo_mysql_node_repository_destroy(&nodes,NULL));CHECK(vireo_mysql_user_repository_destroy(&users,NULL));bool closed=false;CHECK(vireo_mysql_pool_close(pool,&closed,NULL));assert(closed);CHECK(vireo_mysql_pool_destroy(thread,&pool,NULL));CHECK(vireo_mysql_connection_destroy(thread,&connection_handle));CHECK(vireo_mysql_thread_detach(&thread));CHECK(vireo_mysql_runtime_destroy(&runtime));memset(phc,0,sizeof(phc));memset(password,0,sizeof(password));return 0;
}
