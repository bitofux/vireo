/* PROJECT: VIREO; FILE: auth_main.c; AUTHOR: bitofux; DATE: 2026-10-20. */
#include "auth_process.h"
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
/** 严格无符号十进制，不接收符号、空白或溢出。 */
static int positive(char const *text,uint64_t *value)
{
    uint64_t n=0;
    if (!*text) return 0;
    for (;*text;++text) {
        if (*text<'0' || *text>'9' || n>(UINT64_MAX-(uint64_t)(*text-'0'))/10) return 0;
        n=n*10+(uint64_t)(*text-'0');
    }
    *value=n; return n!=0;
}
int main(int argc,char **argv)
{
    if (argc==2 && !strcmp(argv[1],"--help")) {
        puts("usage: vireo-auth-server ADDRESS PORT CERT_FILE KEY_FILE MYSQL_SOCKET MYSQL_USER PASSWORD_FILE DATABASE SESSION_LIFETIME_MS");
        return EXIT_SUCCESS;
    }
    uint64_t port=0,lifetime=0;
    if (argc!=10 || !positive(argv[2],&port) || port>UINT16_MAX || !positive(argv[9],&lifetime)) {
        fputs("vireo-auth-server invalid arguments; use --help\n",stderr); return EXIT_FAILURE;
    }
    vireo_auth_process_options_t const options={argv[1],(uint16_t)port,argv[3],argv[4],argv[5],argv[6],argv[7],argv[8],lifetime,4096,NULL,NULL,4096,4096,32768};
    vireo_auth_process_report_t r;
    vireo_result_t rc=vireo_auth_process_run(&options,&r);
    fprintf(stderr,"vireo-auth-server exit result=%d phase=%d ready=%d clean=%d signal=%d faults_at_stop=%u final_faults=%u created=%zu joined=%zu worker=%d cleanup=%d\n",
        (int)rc,(int)r.phase,r.ready,r.clean,r.stop_signal,r.faults_at_stop,r.final_faults,r.created_count,r.joined_count,(int)r.first_worker_result,(int)r.cleanup_result);
    fprintf(stderr,"vireo-auth-server directory stat_faults_at_stop=%u stat_final_faults=%u queues_closed=%u queues_drained=%u final_drain_turns=%zu\n",
        r.stat_faults_at_stop,r.stat_final_faults,r.queues_closed,r.queues_drained,r.final_drain_turns);
    fprintf(stderr,"vireo-auth-server root root_faults_at_stop=%u root_final_faults=%u\n",r.root_faults_at_stop,r.root_final_faults);
    fprintf(stderr,"vireo-auth-server list list_faults_at_stop=%u list_final_faults=%u\n",r.list_faults_at_stop,r.list_final_faults);
    fprintf(stderr,"vireo-auth-server audit audit_disabled=%d audit_result=%d audit_created=%d audit_joined=%d audit_queued=%" PRIu64
        " audit_taken=%" PRIu64 " audit_discarded=%" PRIu64 " audit_committed=%" PRIu64 " audit_failed=%" PRIu64 " audit_unknown=%" PRIu64 "\n",
        r.audit_writer.disabled,(int)r.audit_writer.first_result,r.audit_writer.created,r.audit_writer.joined,
        r.audit_queue.queued,r.audit_queue.taken,r.audit_queue.discarded_on_close,
        r.audit_writer.committed,r.audit_writer.failed,r.audit_writer.unknown);
    fprintf(stderr,"vireo-auth-server audit audit_rate=%" PRIu64 " audit_full=%" PRIu64
        " audit_contention=%" PRIu64 " audit_closed=%" PRIu64 " audit_disabled_drop=%" PRIu64 "\n",
        r.audit_queue.dropped_rate,r.audit_queue.dropped_full,r.audit_queue.dropped_contention,
        r.audit_queue.dropped_closed,r.audit_queue.dropped_disabled);
    return rc==VIREO_OK?EXIT_SUCCESS:EXIT_FAILURE;
}
