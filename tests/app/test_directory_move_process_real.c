/* PROJECT: VIREO; FILE: test_directory_move_process_real.c; AUTHOR: bitofux; DATE: 2026-10-20.
 * 每个生命周期使用全新exec进程；正常返回前检查FD而非依靠OS退出回收。 */
#define _GNU_SOURCE
#include "auth_process.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <vireo/base/clock.h>
#include <vireo/service/directory_move_completion.h>
/* 仅本测试helper链接替换；产品库/生产binary无此接点或环境分支。
 * 真正SQL已返回后暂缓publication，父进程独立查receipt再推进测试时钟。 */
vireo_result_t __real_vireo_clock_monotonic_now(vireo_monotonic_ns_t *,vireo_clock_error_t *);
vireo_result_t __wrap_vireo_clock_monotonic_now(vireo_monotonic_ns_t *out,vireo_clock_error_t *error)
{
    int const saved=errno;char const *barrier=getenv("VIREO_MOVE_TEST_BARRIER");
    bool const advanced=barrier && access(barrier,F_OK)==0;
    vireo_result_t const rc=__real_vireo_clock_monotonic_now(out,error);
    if(rc==VIREO_OK && advanced) { if(*out>UINT64_MAX-UINT64_C(11000000000)) abort();*out+=UINT64_C(11000000000); }
    errno=saved;return rc;
}
vireo_result_t __real_vireo_directory_move_completion_publish(vireo_task_t const *,uint32_t,
    vireo_directory_move_task_result_t const *,size_t,vireo_completion_queue_t *,vireo_notifier_t *,
    vireo_completion_t **,vireo_directory_move_completion_publish_report_t *);
vireo_result_t __wrap_vireo_directory_move_completion_publish(vireo_task_t const *task,uint32_t op,
    vireo_directory_move_task_result_t const *result,size_t budget,vireo_completion_queue_t *queue,
    vireo_notifier_t *notifier,vireo_completion_t **remaining,vireo_directory_move_completion_publish_report_t *report)
{
    int const saved=errno;char const *barrier=getenv("VIREO_MOVE_TEST_BARRIER");
    if(barrier) {
        uint64_t start=0,now=0;
        if(__real_vireo_clock_monotonic_now(&start,NULL)!=VIREO_OK) abort();
        while(access(barrier,F_OK)!=0) {
            struct timespec pause={0,1000000};(void)nanosleep(&pause,NULL);
            if(__real_vireo_clock_monotonic_now(&now,NULL)!=VIREO_OK || now-start>UINT64_C(10000000000)) abort();
        }
    }
    errno=saved;return __real_vireo_directory_move_completion_publish(task,op,result,budget,queue,notifier,remaining,report);
}
static size_t fds(void)
{
    DIR *d=opendir("/proc/self/fd"); if (!d) abort();
    size_t n=0; struct dirent *entry;
    while ((entry=readdir(d))!=NULL) if (entry->d_name[0]!='.') ++n;
    if (closedir(d)!=0) abort();
    return n;
}
static void observe_audit(void *context,vireo_auth_failure_audit_info_t const *info)
{
    bool *reported=context;
    if(info->disabled && !*reported) {
        *reported=true;
        if(puts("vireo-auth-test audit-disabled")<0 || fflush(stdout)!=0) abort();
    }
}
int main(int argc,char **argv)
{
    if (argc==17 && !strcmp(argv[1],"--child")) {
        size_t const before=fds();
        bool reported=false;
        vireo_auth_process_options_t const o={argv[2],(uint16_t)strtoul(argv[3],NULL,10),argv[4],argv[5],argv[6],argv[7],argv[8],argv[9],
            (uint64_t)strtoull(argv[10],NULL,10),(size_t)strtoull(argv[11],NULL,10),observe_audit,&reported,
            (size_t)strtoull(argv[12],NULL,10),(size_t)strtoull(argv[13],NULL,10),(size_t)strtoull(argv[14],NULL,10),(size_t)strtoull(argv[15],NULL,10),(size_t)strtoull(argv[16],NULL,10),0};
        vireo_auth_process_report_t r; errno=EDOM;
        vireo_result_t rc=vireo_auth_process_run(&o,&r);
        if (errno!=EDOM) abort();
        size_t const after=fds();
        fprintf(stderr,"auth_process child result=%d phase=%d ready=%d clean=%d signal=%d faults_at_stop=%u final_faults=%u created=%zu joined=%zu worker=%d cleanup=%d fd_before=%zu fd_after=%zu\n",
            (int)rc,(int)r.phase,r.ready,r.clean,r.stop_signal,r.faults_at_stop,r.final_faults,r.created_count,r.joined_count,
            (int)r.first_worker_result,(int)r.cleanup_result,before,after);
        fprintf(stderr,"stat_faults_at_stop=%u stat_final_faults=%u queues_closed=%u queues_drained=%u final_drain_turns=%zu\n",
            r.stat_faults_at_stop,r.stat_final_faults,r.queues_closed,r.queues_drained,r.final_drain_turns);
        fprintf(stderr,"root_faults_at_stop=%u root_final_faults=%u\n",r.root_faults_at_stop,r.root_final_faults);
        fprintf(stderr,"list_faults_at_stop=%u list_final_faults=%u\n",r.list_faults_at_stop,r.list_final_faults);
        fprintf(stderr,"mkdir_faults_at_stop=%u mkdir_final_faults=%u\n",r.mkdir_faults_at_stop,r.mkdir_final_faults);
        fprintf(stderr,"move_faults_at_stop=%u move_final_faults=%u\n",r.move_faults_at_stop,r.move_final_faults);
        fprintf(stderr,"audit_disabled=%d audit_result=%d audit_created=%d audit_joined=%d audit_queued=%llu audit_taken=%llu audit_discarded=%llu audit_committed=%llu audit_failed=%llu audit_unknown=%llu\n",
            r.audit_writer.disabled,(int)r.audit_writer.first_result,r.audit_writer.created,r.audit_writer.joined,
            (unsigned long long)r.audit_queue.queued,(unsigned long long)r.audit_queue.taken,
            (unsigned long long)r.audit_queue.discarded_on_close,(unsigned long long)r.audit_writer.committed,
            (unsigned long long)r.audit_writer.failed,(unsigned long long)r.audit_writer.unknown);
        if (before!=after || !r.clean || r.created_count!=r.joined_count ||
            r.audit_writer.created!=r.audit_writer.joined ||
            r.audit_queue.queued!=r.audit_queue.taken+r.audit_queue.discarded_on_close) abort();
        if (r.ready && (r.queues_closed!=127 || r.queues_drained!=126 || !r.final_drain_turns)) abort();
        return rc==VIREO_OK?0:1;
    }
    if (argc!=5) abort();
    char self[4096]; ssize_t n=readlink("/proc/self/exe",self,sizeof self-1);
    if (n<=0 || n>=(ssize_t)sizeof self-1) abort();
    self[n]=0;
    char server[4096]; memcpy(server,self,(size_t)n+1);
    char *slash=strrchr(server,'/'); if (!slash) abort();
    size_t prefix=(size_t)(slash-server)+1;
    if (prefix+sizeof "vireo-auth-server">sizeof server) abort();
    memcpy(server+prefix,"vireo-auth-server",sizeof "vireo-auth-server");
    execlp("python3","python3",VIREO_AUTH_PROCESS_TEST_SCRIPT,"--real",server,self,argv[1],argv[2],argv[3],argv[4],(char *)NULL);
    abort();
}
