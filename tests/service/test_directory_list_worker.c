/* PROJECT : VIREO; FILE : test_directory_list_worker.c; AUTHOR : bitofux;
 * DATE : 2026-10-23; BRIEF : 单次worker的首错、真实owner、原线程销毁及清理门禁故障矩阵。 */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include "directory_list_bridge_test_support.h"
#include "directory_list_task_internal.h"
#include "directory_list_worker_internal.h"
static max_align_t markers[7];
typedef struct scenario {
    unsigned attach, repository, clock, execute, destroy_repo, detach, publish, destroy_completion;
    unsigned released;
    size_t allocated;
    vireo_result_t attach_rc, repo_rc, clock_rc, work_rc, destroy_rc, detach_rc, publish_rc,
        completion_rc;
    bool fail_alloc, keep_repo, keep_guard, keep_completion, retain_completion, history_cleanup;
    bool child_on_failure;
} scenario_t;
static void *allocate(void *c, size_t n) {
    scenario_t *s = c;
    if (s->fail_alloc)
        return NULL;
    s->allocated = n;
    return malloc(n);
}
static void release(void *c, void *p) {
    scenario_t *s = c;
    assert(vireo_list_zero(p, s->allocated));
    ++s->released;
    free(p);
}
static vireo_result_t attach(void *c, vireo_mysql_runtime_t *r, vireo_mysql_thread_t **g,
                             vireo_mysql_error_t *e) {
    scenario_t *s = c;
    assert(r == (void *)&markers[0] && !*g);
    ++s->attach;
    if (s->attach_rc == VIREO_OK || s->child_on_failure)
        *g = (void *)&markers[5];
    if (s->attach_rc != VIREO_OK)
        e->stage = VIREO_MYSQL_STAGE_THREAD_INIT;
    errno = EIO;
    return s->attach_rc;
}
static vireo_result_t repository(void *c, vireo_mysql_thread_t *g, vireo_mysql_pool_t *p,
                                 vireo_mysql_node_repository_t **r, vireo_mysql_node_error_t *e) {
    scenario_t *s = c;
    assert(g == (void *)&markers[5] && p == (void *)&markers[1] && !*r);
    ++s->repository;
    if (s->repo_rc == VIREO_OK || s->child_on_failure)
        *r = (void *)&markers[6];
    if (s->repo_rc != VIREO_OK)
        e->stage = VIREO_MYSQL_NODE_STAGE_ALLOCATE;
    errno = EIO;
    return s->repo_rc;
}
static vireo_result_t clock_read(void *c, uint64_t *now, vireo_clock_error_t *e) {
    scenario_t *s = c;
    ++s->clock;
    if (s->clock_rc)
        e->stage = VIREO_CLOCK_STAGE_READ;
    *now = 17;
    errno = EIO;
    return s->clock_rc;
}
static vireo_result_t execute(void *c, const vireo_task_t *t,
                              const vireo_directory_list_task_options_t *o,
                              vireo_mysql_node_repository_t *r, const vireo_page_token_key_t *k,
                              uint64_t now, vireo_directory_list_task_result_t *v) {
    scenario_t *s = c;
    assert(o->list_operation == OP && o->pool_timeout_ms == 17 && r == (void *)&markers[6] &&
           k == (void *)&markers[2] && now == 17);
    ++s->execute;
    make_page_result(t, 2, false, v);
    if (s->work_rc) {
        memset(&v->service, 0, sizeof(v->service));
        v->result = s->work_rc;
        v->stage = VIREO_DIRECTORY_LIST_TASK_CONTEXT;
    }
    if (s->history_cleanup) {
        memset(&v->service, 0, sizeof(v->service));
        v->stage = VIREO_DIRECTORY_LIST_TASK_SERVICE;
        v->result = VIREO_RESULT_DATABASE;
        v->service.repository_operation = VIREO_DIRECTORY_LIST_REPOSITORY_CHILDREN;
        v->service.repository.cleanup_pending = true;
        v->error.repository.cleanup_result = VIREO_RESULT_DATABASE;
    }
    errno = EIO;
    return v->result;
}
static vireo_result_t destroy_repo(void *c, vireo_mysql_node_repository_t **r,
                                   vireo_mysql_node_error_t *e) {
    scenario_t *s = c;
    assert(*r == (void *)&markers[6]);
    ++s->destroy_repo;
    if (!s->keep_repo)
        *r = NULL;
    if (s->destroy_rc)
        e->cleanup_result = s->destroy_rc;
    errno = EIO;
    return s->destroy_rc;
}
static vireo_result_t detach(void *c, vireo_mysql_thread_t **g) {
    scenario_t *s = c;
    assert(*g == (void *)&markers[5]);
    ++s->detach;
    if (!s->keep_guard)
        *g = NULL;
    errno = EIO;
    return s->detach_rc;
}
static vireo_result_t publish(void *c, const vireo_task_t *t, uint32_t op,
                              const vireo_directory_list_task_result_t *v, size_t budget,
                              vireo_completion_queue_t *q, vireo_notifier_t *n,
                              vireo_completion_t **owner,
                              vireo_directory_list_completion_publish_report_t *p) {
    scenario_t *s = c;
    assert(s->detach == (unsigned)(s->attach_rc == VIREO_OK || s->child_on_failure) &&
           !s->keep_repo && !s->keep_guard && !s->destroy_rc && !s->detach_rc && budget == BUDGET &&
           q == (void *)&markers[3] && n == (void *)&markers[4] && op == OP);
    ++s->publish;
    if (s->history_cleanup)
        assert(v->error.repository.cleanup_result == VIREO_RESULT_DATABASE &&
               v->service.repository.cleanup_pending && !v->service.outcome);
    if (s->retain_completion) {
        vireo_task_info_t info;
        CHECK(vireo_task_inspect(t, &info), VIREO_OK);
        vireo_completion_metadata_t m;
        CHECK(vireo_completion_metadata_make(info.metadata, v->result, VIREO_STATUS_INTERNAL_ERROR,
                                             &m),
              VIREO_OK);
        CHECK(vireo_completion_create_copy(m, NULL, 0, BUDGET, owner), VIREO_OK);
        p->publication.completion_retained = true;
    } else
        p->publication.completion_transferred = true;
    errno = EIO;
    return s->publish_rc;
}
static vireo_result_t destroy_completion(void *c, vireo_completion_t **p) {
    scenario_t *s = c;
    ++s->destroy_completion;
    if (!s->keep_completion)
        CHECK(vireo_completion_destroy(p), VIREO_OK);
    errno = EIO;
    return s->completion_rc;
}
static vireo_directory_list_worker_ops_t operations(scenario_t *s) {
    return (vireo_directory_list_worker_ops_t){
        s,       allocate,     release, attach,  repository,        clock_read,
        execute, destroy_repo, detach,  publish, destroy_completion};
}
static const vireo_directory_list_worker_resources_t resources = {
    (void *)&markers[0], (void *)&markers[2], (void *)&markers[1], (void *)&markers[3],
    (void *)&markers[4]};
static const vireo_directory_list_worker_options_t options = {{OP, 17}, BUDGET, BUDGET};
typedef struct foreign_call {
    vireo_directory_list_worker_t *worker;
    const vireo_task_t *task;
} foreign_call_t;
static void *foreign(void *c) {
    foreign_call_t *f = c;
    vireo_directory_list_worker_report_t report;
    CHECK(vireo_directory_list_worker_run(f->worker, f->task, &report),
          VIREO_RESULT_INVALID_ARGUMENT);
    assert(!report.attempted);
    vireo_directory_list_worker_t *alias = f->worker;
    vireo_directory_list_worker_cleanup_report_t cleanup;
    CHECK(vireo_directory_list_worker_destroy(&alias, &cleanup), VIREO_RESULT_INVALID_ARGUMENT);
    assert(alias == f->worker);
    return NULL;
}
int main(void) {
    int old_state;
    assert(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state) == 0);
    vireo_task_t *task = make_task(1, true, NULL);
    for (size_t i = 0; i < 16; ++i) {
        scenario_t s = {0};
        switch (i) {
            case 1:
                s.attach_rc = VIREO_RESULT_NO_MEMORY;
                break;
            case 2:
                s.repo_rc = VIREO_RESULT_NO_MEMORY;
                break;
            case 3:
                s.clock_rc = VIREO_RESULT_IO;
                break;
            case 4:
                s.work_rc = VIREO_RESULT_TIMEOUT;
                break;
            case 5:
                s.destroy_rc = VIREO_RESULT_DATABASE;
                break;
            case 6:
                s.detach_rc = VIREO_RESULT_INTERNAL;
                break;
            case 7:
                s.publish_rc = VIREO_RESULT_IO;
                break; /* 交接后的通知失败。 */
            case 8:
                s.publish_rc = VIREO_RESULT_CANCELLED;
                s.retain_completion = true;
                break;
            case 9:
                s.keep_repo = true;
                break; /* OK但owner残留也不得发布。 */
            case 10:
                s.keep_guard = true;
                break;
            case 11:
                s.destroy_rc = VIREO_RESULT_BUSY;
                s.keep_repo = true;
                break;
            case 12:
                s.work_rc = VIREO_RESULT_DATABASE;
                s.destroy_rc = VIREO_RESULT_IO;
                break;
            case 13:
                s.history_cleanup = true;
                break;
            case 14:
                s.attach_rc = VIREO_RESULT_DATABASE;
                s.child_on_failure = true;
                break;
            case 15:
                s.repo_rc = VIREO_RESULT_DATABASE;
                s.child_on_failure = true;
                break;
            default:
                break;
        }
        vireo_directory_list_worker_ops_t ops = operations(&s);
        vireo_directory_list_worker_t *worker = NULL;
        CHECK(vireo_directory_list_worker_create_with(&resources, &options, &worker, &ops),
              VIREO_OK);
        if (!i) {
            foreign_call_t f = {worker, task};
            pthread_t thread;
            assert(pthread_create(&thread, NULL, foreign, &f) == 0 &&
                   pthread_join(thread, NULL) == 0);
        }
        vireo_directory_list_worker_report_t report, again;
        vireo_result_t want = s.attach_rc                     ? s.attach_rc
                              : s.repo_rc                     ? s.repo_rc
                              : s.clock_rc                    ? s.clock_rc
                              : s.work_rc                     ? s.work_rc
                              : s.history_cleanup             ? VIREO_RESULT_DATABASE
                              : s.destroy_rc                  ? s.destroy_rc
                              : s.detach_rc                   ? s.detach_rc
                              : (s.keep_repo || s.keep_guard) ? VIREO_RESULT_INTERNAL
                                                              : s.publish_rc;
        CHECK(vireo_directory_list_worker_run(worker, task, &report), want);
        assert(report.attempted && report.task_validated && s.attach == 1 &&
               report.publication_blocked_by_cleanup ==
                   (s.destroy_rc || s.detach_rc || s.keep_repo || s.keep_guard));
        CHECK(vireo_directory_list_worker_run(worker, task, &again), VIREO_RESULT_BUSY);
        assert(again.work_result == report.work_result && s.attach == 1);
        vireo_directory_list_worker_cleanup_report_t cleanup;
        if (s.keep_repo || s.keep_guard) {
            CHECK(vireo_directory_list_worker_destroy(&worker, &cleanup),
                  s.destroy_rc ? s.destroy_rc : VIREO_RESULT_INTERNAL);
            assert(worker && !s.released);
        }
        s.keep_repo = false;
        s.keep_guard = false;
        s.destroy_rc = VIREO_OK;
        s.detach_rc = VIREO_OK;
        if (i == 8) {
            s.keep_completion = true;
            s.completion_rc = VIREO_RESULT_BUSY;
            CHECK(vireo_directory_list_worker_destroy(&worker, &cleanup), VIREO_RESULT_BUSY);
            assert(worker && cleanup.completion_pending);
            s.keep_completion = false;
            s.completion_rc = VIREO_RESULT_DATABASE;
        }
        CHECK(vireo_directory_list_worker_destroy(&worker, &cleanup), s.completion_rc);
        assert(!worker && s.released == 1 && s.publish <= 1 && s.execute <= 1);
        if (i == 9 || i == 11)
            assert(s.detach == 1);
    }
    scenario_t s = {.fail_alloc = true};
    vireo_directory_list_worker_ops_t ops = operations(&s);
    vireo_directory_list_worker_t *worker = NULL;
    CHECK(vireo_directory_list_worker_create_with(&resources, &options, &worker, &ops),
          VIREO_RESULT_NO_MEMORY);
    vireo_directory_list_worker_options_t small = options;
    small.max_memory_bytes = 1;
    CHECK(vireo_directory_list_worker_create_with(&resources, &small, &worker, &ops),
          VIREO_RESULT_RANGE);
    s.fail_alloc = false;
    CHECK(vireo_directory_list_worker_create_with(&resources, &options, &worker, &ops), VIREO_OK);
    vireo_task_t *bad = NULL;
    CHECK(vireo_task_create_copy(metadata(4), "VLT1", 4, BUDGET, &bad), VIREO_OK);
    vireo_directory_list_worker_report_t report;
    CHECK(vireo_directory_list_worker_run(worker, bad, &report), VIREO_RESULT_PROTOCOL);
    assert(report.attempted && !report.attach_called && !report.publish_called && !s.attach);
    CHECK(vireo_directory_list_worker_run(worker, task, &report), VIREO_RESULT_BUSY);
    vireo_directory_list_worker_cleanup_report_t cleanup;
    CHECK(vireo_directory_list_worker_destroy(&worker, &cleanup), VIREO_OK);
    CHECK(vireo_task_destroy(&bad), VIREO_OK);
    CHECK(vireo_task_destroy(&task), VIREO_OK);
    printf("worker allocation=%zu; task result=%zu; report=%zu\n", s.allocated,
           sizeof(vireo_directory_list_task_result_t),
           sizeof(vireo_directory_list_worker_report_t));
    printf(
        "PASS %zu LIST worker checks; 16 owner/failure paths, one-shot, original thread, clear and "
        "no replay\n",
        checks);
    assert(pthread_setcancelstate(old_state, NULL) == 0);
    return 0;
}
