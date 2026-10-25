/* Worker ownership and failure gates; dependencies use private synchronous seams. */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include "directory_remove_worker_internal.h"

typedef struct model {
    max_align_t storage;
    size_t attached, created, randoms, clocks, executed, published, destroyed, detached, discarded;
    unsigned random_mode;
    vireo_result_t attach_rc, create_rc, clock_rc, cleanup_rc, detach_rc, publish_rc;
    bool keep_repository, keep_guard, leave_completion;
} model_t;
static void *alloc(void *c, size_t n) { (void)c; return calloc(1, n); }
static void release(void *c, void *p) { (void)c; free(p); }
static vireo_result_t attach(void *c, vireo_mysql_runtime_t *r, vireo_mysql_thread_t **o,
                             vireo_mysql_error_t *e) {
    model_t *m = c; (void)r; (void)e; ++m->attached;
    if (!m->attach_rc) *o = (vireo_mysql_thread_t *)(void *)&m->storage;
    errno = EIO; return m->attach_rc;
}
static vireo_result_t repo_create(void *c, vireo_mysql_thread_t *t, vireo_mysql_pool_t *p,
                                  vireo_mysql_node_repository_t **o, vireo_mysql_node_error_t *e) {
    model_t *m = c; (void)p; (void)e; assert(t); ++m->created;
    if (!m->create_rc) *o = (vireo_mysql_node_repository_t *)(void *)&m->storage;
    errno = EIO; return m->create_rc;
}
static int random_bytes(void *c, unsigned char o[16]) {
    model_t *m = c; assert(m->created == 1 && !m->clocks); ++m->randoms;
    memset(o, m->random_mode == 2 ? 0 : 0x31, 16);
    errno = EIO; return m->random_mode == 1 ? 0 : 1;
}
static vireo_result_t clock_now(void *c, uint64_t *n, vireo_clock_error_t *e) {
    model_t *m = c; (void)e; assert(m->randoms == 1); ++m->clocks; *n = 1;
    errno = EIO; return m->clock_rc;
}
static vireo_result_t execute(void *c, const vireo_task_t *t,
                              const vireo_directory_remove_task_options_t *o,
                              vireo_mysql_node_repository_t *r, const unsigned char event[16],
                              uint64_t now, vireo_directory_remove_task_result_t *out) {
    model_t *m = c; assert(t && r && m->clocks == 1 && now == 1 && o->remove_operation == 404);
    for (size_t i = 0; i < 16; ++i) assert(event[i] == 0x31);
    ++m->executed; out->stage = VIREO_DIRECTORY_REMOVE_TASK_SERVICE; out->result = VIREO_OK;
    assert(vireo_directory_remove_task_read(t,404,&out->input,&out->request_issue)==VIREO_OK);
    out->service=(vireo_directory_remove_result_t){.outcome=VIREO_DIRECTORY_REMOVE_APPLIED,
        .node_id=out->input.request.node_id,.audit_id=8,.repository_called=true,
        .repository_result=VIREO_OK,.repository={.commit=VIREO_MYSQL_NODE_SOFT_DELETE_COMMITTED,
        .effect=VIREO_MYSQL_NODE_REMOVE_EFFECT_APPLIED,.node_id=out->input.request.node_id,.audit_id=8}};
    memcpy(out->service.idempotency_key,out->input.request.idempotency_key,16);
    errno = EIO; return VIREO_OK;
}
static vireo_result_t repo_destroy(void *c, vireo_mysql_node_repository_t **o,
                                   vireo_mysql_node_error_t *e) {
    model_t *m = c; (void)e; ++m->destroyed;
    if (!m->keep_repository) *o = NULL;
    errno = EIO; return m->cleanup_rc;
}
static vireo_result_t detach(void *c, vireo_mysql_thread_t **o) {
    model_t *m = c; ++m->detached;
    if (!m->keep_guard) *o = NULL;
    errno = EIO; return m->detach_rc;
}
static vireo_result_t publish(void *c, const vireo_task_t *t, uint32_t op,
                              const vireo_directory_remove_task_result_t *r, size_t b,
                              vireo_completion_queue_t *q, vireo_notifier_t *n,
                              vireo_completion_t **left,
                              vireo_directory_remove_completion_publish_report_t *p) {
    model_t *m = c; (void)t; (void)op; (void)b; (void)q; (void)n;
    assert(m->detached || !m->created); ++m->published;
    assert(r->result == VIREO_OK || r->service.outcome == VIREO_DIRECTORY_REMOVE_NONE);
    p->task_matched = p->result_validated = p->publish_called = true;
    p->publication.completion_transferred = !m->leave_completion;
    if (m->leave_completion) *left = (vireo_completion_t *)(void *)&m->storage;
    errno = EIO; return m->publish_rc;
}
static vireo_result_t completion_destroy(void *c, vireo_completion_t **o) {
    model_t *m = c; ++m->discarded; *o = NULL; errno = EIO; return VIREO_OK;
}
static vireo_directory_remove_worker_t *make_worker(model_t *m) {
    vireo_directory_remove_worker_resources_t resources={(void*)1,(void*)2,(void*)3,(void*)4};
    vireo_directory_remove_worker_options_t options={.execution={404,17},
        .completion_allocation_budget=4096,.max_memory_bytes=65536};
    const vireo_directory_remove_worker_ops_t ops={.context=m,.allocate=alloc,.release=release,
        .attach=attach,.repository_create=repo_create,.random=random_bytes,.clock=clock_now,
        .execute=execute,.repository_destroy=repo_destroy,.detach=detach,.publish=publish,
        .completion_destroy=completion_destroy};
    vireo_directory_remove_worker_t *w=NULL;
    assert(vireo_directory_remove_worker_create_with(&resources,&options,&w,&ops)==VIREO_OK);
    return w;
}
typedef struct foreign_call { vireo_directory_remove_worker_t *worker; vireo_task_t *task; } foreign_call_t;
static void *foreign_thread(void *arg) {
    foreign_call_t *c = arg;
    vireo_directory_remove_worker_report_t report;
    assert(vireo_directory_remove_worker_run(c->worker,c->task,&report)==VIREO_RESULT_INVALID_ARGUMENT);
    assert(!report.attempted);
    vireo_directory_remove_worker_t *owner=c->worker;
    vireo_directory_remove_worker_cleanup_report_t cleanup;
    assert(vireo_directory_remove_worker_destroy(&owner,&cleanup)==VIREO_RESULT_INVALID_ARGUMENT);
    assert(owner==c->worker); return NULL;
}
int main(void) {
    vireo_node_remove_request_t req={.sequence=11,.session_handle=9,.node_id=123};
    memset(req.idempotency_key,1,16); unsigned char wire[64]; size_t size=0;
    assert(vireo_node_remove_request_encode(&req,wire,64,&size)==VIREO_OK);
    vireo_task_metadata_t metadata={.route={1,0,3,11},.request_instance_id=9,.operation=404,.deadline_ns=100};
    vireo_mysql_node_actor_t actor={7,51}; vireo_task_t *task=NULL;
    assert(vireo_directory_remove_task_create(metadata,404,wire,size,&actor,4096,NULL,&task)==VIREO_OK);
    for (unsigned mode=0; mode<12; ++mode) {
        model_t m={0}; vireo_result_t expected=VIREO_OK;
        switch(mode) {
            case 1: m.random_mode=1; expected=VIREO_RESULT_IO; break;
            case 2: m.random_mode=2; expected=VIREO_RESULT_IO; break;
            case 3: m.clock_rc=VIREO_RESULT_IO; expected=VIREO_RESULT_IO; break;
            case 4: m.attach_rc=VIREO_RESULT_BUSY; expected=VIREO_RESULT_BUSY; break;
            case 5: m.create_rc=VIREO_RESULT_NO_MEMORY; expected=VIREO_RESULT_NO_MEMORY; break;
            case 6: m.cleanup_rc=VIREO_RESULT_IO; m.keep_repository=true; expected=VIREO_RESULT_IO; break;
            case 7: m.keep_repository=true; expected=VIREO_RESULT_INTERNAL; break;
            case 8: m.detach_rc=VIREO_RESULT_IO; expected=VIREO_RESULT_IO; break;
            case 9: m.keep_guard=true; expected=VIREO_RESULT_INTERNAL; break;
            case 10: m.publish_rc=VIREO_RESULT_IO; expected=VIREO_RESULT_IO; break;
            case 11: m.publish_rc=VIREO_RESULT_NO_MEMORY; m.leave_completion=true; expected=VIREO_RESULT_NO_MEMORY; break;
            default: break;
        }
        vireo_directory_remove_worker_t *w=make_worker(&m);
        if (!mode) {
            foreign_call_t c={w,task}; pthread_t thread;
            assert(!pthread_create(&thread,NULL,foreign_thread,&c)); assert(!pthread_join(thread,NULL));
            assert(!m.attached);
        }
        errno=EDOM; vireo_directory_remove_worker_report_t report;
        assert(vireo_directory_remove_worker_run(w,task,&report)==expected && errno==EDOM);
        assert(report.attempted && report.task_validated && m.attached==1);
        if (mode==1 || mode==2) assert(m.randoms==1 && !m.clocks && !m.executed);
        if (mode==3) assert(m.clocks==1 && !m.executed);
        if (mode==4) assert(!m.created && !m.randoms && !m.executed);
        if (mode==5) assert(m.created==1 && !m.randoms && !m.executed && m.detached==1);
        if (mode>=6 && mode<=9) {
            assert(report.publication_blocked_by_cleanup && !report.publish_called && !m.published);
            assert(report.service.repository.commit==VIREO_MYSQL_NODE_SOFT_DELETE_COMMITTED);
            if (mode==6 || mode==7) assert(!m.detached && report.cleanup.repository_pending);
        } else assert(report.publish_called && m.published==1);
        if (mode==10) assert(report.publication.publication.completion_transferred && !report.completion_pending);
        if (mode==11) assert(report.completion_pending && !report.publication.publication.completion_transferred);
        size_t executed=m.executed, published=m.published, destroyed=m.destroyed;
        assert(vireo_directory_remove_worker_run(w,task,&report)==VIREO_RESULT_BUSY && errno==EDOM);
        assert(m.executed==executed && m.published==published && m.destroyed==destroyed);
        m.keep_repository=m.keep_guard=false; m.cleanup_rc=m.detach_rc=VIREO_OK;
        vireo_directory_remove_worker_cleanup_report_t cleanup;
        assert(vireo_directory_remove_worker_destroy(&w,&cleanup)==VIREO_OK && !w && errno==EDOM);
        assert(m.executed==executed && m.published==published);
        assert(m.discarded==(mode==11 ? 1u : 0u));
    }
    assert(vireo_task_destroy(&task)==VIREO_OK); return 0;
}
