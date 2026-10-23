/*
 * PROJECT : VIREO
 * FILE    : test_directory_root_worker.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-22
 * BRIEF   : 根查询桥接边界与资源验证。
 */
#include <pthread.h>
#include "directory_root_test_support.h"
#include "directory_root_worker_internal.h"
typedef struct model {
    vireo_directory_root_worker_resources_t resources;
    vireo_directory_root_worker_options_t options;
    max_align_t guard, repo;
    size_t allocated, freed, attached, created, clocks, executed, destroyed, detached, published,
        completion_destroyed;
    int step;
    unsigned fail_repo, fail_detach, fail_completion;
    bool no_memory, consume_repo, consume_guard, leave_ok_repo, leave_ok_guard, notify_fail,
        dirty_service;
    vireo_result_t attach_rc, create_rc, clock_rc, work_rc;
} model_t;
static void *allocate(void *c, size_t size) {
    model_t *m = c;
    ++m->allocated;
    errno = EIO;
    return m->no_memory ? NULL : calloc(1, size);
}
static void release(void *c, void *p) {
    model_t *m = c;
    ++m->freed;
    free(p);
    errno = EIO;
}
static vireo_result_t attach(void *c, vireo_mysql_runtime_t *r, vireo_mysql_thread_t **t,
                             vireo_mysql_error_t *e) {
    model_t *m = c;
    (void)e;
    assert(r == m->resources.runtime && !*t && m->step == 0);
    m->step = 1;
    ++m->attached;
    if (!m->attach_rc)
        *t = (vireo_mysql_thread_t *)&m->guard;
    errno = EIO;
    return m->attach_rc;
}
static vireo_result_t create(void *c, vireo_mysql_thread_t *t, vireo_mysql_pool_t *p,
                             vireo_mysql_node_repository_t **r, vireo_mysql_node_error_t *e) {
    model_t *m = c;
    (void)e;
    assert(t == (vireo_mysql_thread_t *)&m->guard && p == m->resources.database && !*r &&
           m->step == 1);
    m->step = 2;
    ++m->created;
    if (!m->create_rc)
        *r = (vireo_mysql_node_repository_t *)&m->repo;
    errno = EIO;
    return m->create_rc;
}
static vireo_result_t clock_now(void *c, uint64_t *now, vireo_clock_error_t *e) {
    model_t *m = c;
    assert(m->step == 2);
    m->step = 3;
    ++m->clocks;
    if (m->clock_rc) {
        e->stage = VIREO_CLOCK_STAGE_READ;
        e->system_errno = EIO;
    } else
        *now = 1;
    errno = EIO;
    return m->clock_rc;
}
static vireo_result_t execute(void *c, const vireo_task_t *t,
                              const vireo_directory_root_task_options_t *o,
                              vireo_mysql_node_repository_t *repo, uint64_t now,
                              vireo_directory_root_task_result_t *out) {
    model_t *m = c;
    assert(m->step == 3 && now == 1 && repo == (vireo_mysql_node_repository_t *)&m->repo &&
           o->root_operation == 400);
    m->step = 4;
    ++m->executed;
    *out = found_result((vireo_task_t *)t);
    out->result = m->work_rc;
    if (m->work_rc) {
        out->service = (vireo_directory_root_result_t){0};
        out->service.repository_called = true;
        out->service.repository_result = m->work_rc;
    }
    if (m->work_rc == VIREO_RESULT_NOT_FOUND) {
        out->service.outcome = VIREO_DIRECTORY_ROOT_UNAUTHORIZED;
        out->service.repository.rollback_confirmed = true;
        out->service.repository.issue = VIREO_MYSQL_NODE_AUTH_REJECTED;
    }
    if (m->dirty_service) {
        out->error.cleanup_result = VIREO_RESULT_BUSY;
        out->service.repository.cleanup_pending = true;
    }
    errno = EIO;
    return m->work_rc;
}
static vireo_result_t destroy_repo(void *c, vireo_mysql_node_repository_t **r,
                                   vireo_mysql_node_error_t *e) {
    model_t *m = c;
    assert(*r == (vireo_mysql_node_repository_t *)&m->repo);
    ++m->destroyed;
    m->step = 5;
    errno = EIO;
    if (m->leave_ok_repo) {
        m->leave_ok_repo = false;
        return VIREO_OK;
    }
    if (m->fail_repo) {
        --m->fail_repo;
        if (m->consume_repo)
            *r = NULL;
        e->cleanup_result = VIREO_RESULT_DATABASE;
        return VIREO_RESULT_DATABASE;
    }
    *r = NULL;
    return VIREO_OK;
}
static vireo_result_t detach(void *c, vireo_mysql_thread_t **t) {
    model_t *m = c;
    assert(*t == (vireo_mysql_thread_t *)&m->guard);
    ++m->detached;
    m->step = 6;
    errno = EIO;
    if (m->leave_ok_guard) {
        m->leave_ok_guard = false;
        return VIREO_OK;
    }
    if (m->fail_detach) {
        --m->fail_detach;
        if (m->consume_guard)
            *t = NULL;
        return VIREO_RESULT_INTERNAL;
    }
    *t = NULL;
    return VIREO_OK;
}
static vireo_result_t publish(void *c, const vireo_task_t *t, uint32_t op,
                              const vireo_directory_root_task_result_t *r, size_t budget,
                              vireo_completion_queue_t *q, vireo_notifier_t *n,
                              vireo_completion_t **left,
                              vireo_directory_root_completion_publish_report_t *p) {
    model_t *m = c;
    assert((m->step == 1 && m->attach_rc) || m->step == 6);
    ++m->published;
    vireo_result_t rc = vireo_directory_root_completion_publish(t, op, r, budget, q, n, left, p);
    if (m->notify_fail && p->publication.completion_transferred) {
        p->publication.notify_result = VIREO_RESULT_IO;
        return VIREO_RESULT_IO;
    }
    return rc;
}
static vireo_result_t completion_destroy(void *c, vireo_completion_t **o) {
    model_t *m = c;
    ++m->completion_destroyed;
    if (m->fail_completion) {
        --m->fail_completion;
        return VIREO_RESULT_IO;
    }
    return vireo_completion_destroy(o);
}
static void setup(model_t *m, bool prepared) {
    *m = (model_t){0};
    m->resources.runtime = (vireo_mysql_runtime_t *)&m->guard;
    m->resources.database = (vireo_mysql_pool_t *)&m->repo;
    queue_setup(&m->resources.queue, &m->resources.notifier, prepared);
    m->options = (vireo_directory_root_worker_options_t){
        .execution = {400, 17}, .completion_allocation_budget = 4096, .max_memory_bytes = 65536};
}
static vireo_directory_root_worker_t *worker(model_t *m) {
    const vireo_directory_root_worker_ops_t ops = {
        m,      allocate, release,           attach, create, clock_now, execute, destroy_repo,
        detach, publish,  completion_destroy};
    vireo_directory_root_worker_t *w = NULL;
    CHECK(vireo_directory_root_worker_create_with(&m->resources, &m->options, &w, &ops),
          m->no_memory ? VIREO_RESULT_NO_MEMORY : VIREO_OK);
    return w;
}
static void outcome(model_t *m, vireo_result_t rc, vireo_status_t status) {
    vireo_completion_t *c = pop(m->resources.queue);
    vireo_directory_root_completion_outcome_t o;
    CHECK(vireo_directory_root_completion_decode(c, 400, &o), VIREO_OK);
    assert(o.metadata.result == rc && o.response.status == status);
    CHECK(vireo_completion_destroy(&c), VIREO_OK);
    empty(m->resources.queue);
}
static void failures(void) {
    for (unsigned i = 0; i < 19; ++i) {
        model_t m;
        setup(&m, i != 11);
        vireo_result_t expected = VIREO_OK;
        vireo_status_t status = VIREO_STATUS_OK;
        bool blocked = false, delivered = true;
        switch (i) {
            case 0:
                m.attach_rc = VIREO_RESULT_NO_MEMORY;
                expected = m.attach_rc;
                status = VIREO_STATUS_OVERLOADED;
                break;
            case 1:
                m.create_rc = VIREO_RESULT_NO_MEMORY;
                expected = m.create_rc;
                status = VIREO_STATUS_OVERLOADED;
                break;
            case 2:
                m.clock_rc = VIREO_RESULT_IO;
                expected = m.clock_rc;
                status = VIREO_STATUS_INTERNAL_ERROR;
                break;
            case 3:
                m.work_rc = VIREO_RESULT_NOT_FOUND;
                expected = m.work_rc;
                status = VIREO_STATUS_UNAUTHORIZED;
                break;
            case 4:
                m.work_rc = VIREO_RESULT_TIMEOUT;
                expected = m.work_rc;
                status = VIREO_STATUS_TIMEOUT;
                break;
            case 5:
                m.work_rc = VIREO_RESULT_DATABASE;
                m.fail_repo = 2;
                expected = m.work_rc;
                blocked = true;
                break;
            case 6:
                m.fail_repo = 1;
                m.consume_repo = true;
                expected = VIREO_RESULT_DATABASE;
                blocked = true;
                break;
            case 7:
                m.fail_detach = 2;
                expected = VIREO_RESULT_INTERNAL;
                blocked = true;
                break;
            case 8:
                m.fail_detach = 1;
                m.consume_guard = true;
                expected = VIREO_RESULT_INTERNAL;
                blocked = true;
                break;
            case 9:
                m.leave_ok_repo = true;
                expected = VIREO_RESULT_INTERNAL;
                blocked = true;
                break;
            case 10:
                m.leave_ok_guard = true;
                expected = VIREO_RESULT_INTERNAL;
                blocked = true;
                break;
            case 11:
                m.fail_completion = 1;
                expected = VIREO_RESULT_NOT_FOUND;
                delivered = false;
                break;
            case 12: {
                vireo_completion_queue_close_report_t p;
                CHECK(vireo_completion_queue_close(m.resources.queue, &p), VIREO_OK);
                expected = VIREO_RESULT_CANCELLED;
                delivered = false;
                break;
            }
            case 13:
                m.options.completion_allocation_budget = 1;
                expected = VIREO_RESULT_RANGE;
                delivered = false;
                break;
            case 14:
                m.notify_fail = true;
                expected = VIREO_RESULT_IO;
                break;
            case 15:
                m.dirty_service = true;
                m.work_rc = VIREO_RESULT_BUSY;
                expected = m.work_rc;
                status = VIREO_STATUS_INTERNAL_ERROR;
                break;
            case 16:
                m.no_memory = true;
                break;
            case 17:
                m.work_rc = VIREO_RESULT_BUSY;
                m.fail_detach = 1;
                expected = m.work_rc;
                blocked = true;
                break;
            default:
                break;
        }
        if (i == 16) {
            assert(!worker(&m));
            queue_teardown(&m.resources.queue, &m.resources.notifier);
            continue;
        }
        vireo_directory_root_worker_t *w = worker(&m);
        vireo_task_t *t = make_task(100, NULL);
        vireo_directory_root_worker_report_t r;
        CHECK(vireo_directory_root_worker_run(w, t, &r), expected);
        assert(r.attempted && r.task_validated && r.publication_blocked_by_cleanup == blocked);
        assert(m.executed == (i < 3 ? 0u : 1u));
        assert(m.published == (blocked ? 0u : 1u));
        const size_t destroyed = m.destroyed, detached = m.detached;
        CHECK(vireo_directory_root_worker_run(w, t, &r), VIREO_RESULT_BUSY);
        assert(m.destroyed == destroyed && m.detached == detached);
        if (!blocked && delivered)
            outcome(&m, r.work_result, status);
        else
            empty(m.resources.queue);
        if (i == 5 || i == 9)
            assert(r.cleanup.repository_pending && r.cleanup.thread_pending && !m.detached);
        if (i == 11 || i == 12)
            assert(r.completion_pending && r.publication.publication.completion_retained);
        CHECK(vireo_task_destroy(&t), VIREO_OK);
        vireo_directory_root_worker_cleanup_report_t cleanup;
        vireo_result_t next = i == 5    ? VIREO_RESULT_DATABASE
                              : i == 7  ? VIREO_RESULT_INTERNAL
                              : i == 11 ? VIREO_RESULT_IO
                                        : VIREO_OK;
        CHECK(vireo_directory_root_worker_destroy(&w, &cleanup), next);
        if (next != VIREO_OK) {
            assert(w);
            CHECK(vireo_directory_root_worker_destroy(&w, &cleanup), VIREO_OK);
        }
        assert(!w && m.freed == 1 && m.published == (blocked ? 0u : 1u));
        queue_teardown(&m.resources.queue, &m.resources.notifier);
    }
}
/* destroy返回非OK仍可消费最后的子owner，控制块应释放；不得要求再次业务运行。 */
static void consumed_destroy(void) {
    for (unsigned i = 0; i < 2; ++i) {
        model_t m;
        setup(&m, true);
        if (i == 0)
            m.fail_repo = 1;
        else
            m.fail_detach = 1;
        vireo_directory_root_worker_t *w = worker(&m);
        vireo_task_t *t = make_task(100, NULL);
        vireo_directory_root_worker_report_t report;
        const vireo_result_t failure = i == 0 ? VIREO_RESULT_DATABASE : VIREO_RESULT_INTERNAL;
        CHECK(vireo_directory_root_worker_run(w, t, &report), failure);
        assert(report.publication_blocked_by_cleanup && !report.publish_called);
        if (i == 0) {
            m.fail_repo = 1;
            m.consume_repo = true;
        } else {
            m.fail_detach = 1;
            m.consume_guard = true;
        }
        vireo_directory_root_worker_cleanup_report_t cleanup;
        CHECK(vireo_directory_root_worker_destroy(&w, &cleanup), failure);
        assert(!w && m.freed == 1 && !cleanup.repository_pending && !cleanup.thread_pending &&
               !m.published);
        CHECK(vireo_task_destroy(&t), VIREO_OK);
        queue_teardown(&m.resources.queue, &m.resources.notifier);
    }
}
typedef struct foreign {
    vireo_directory_root_worker_t *w;
    vireo_task_t *t;
} foreign_t;
static void *foreign_call(void *p) {
    int old_state = 0;
    assert(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state));
    foreign_t *f = p;
    vireo_directory_root_worker_report_t r;
    CHECK(vireo_directory_root_worker_run(f->w, f->t, &r), VIREO_RESULT_INVALID_ARGUMENT);
    assert(!r.attempted);
    vireo_directory_root_worker_t *w = f->w;
    vireo_directory_root_worker_cleanup_report_t c;
    CHECK(vireo_directory_root_worker_destroy(&w, &c), VIREO_RESULT_INVALID_ARGUMENT);
    assert(w == f->w);
    return NULL;
}
static void invalid(void) {
    model_t m;
    setup(&m, true);
    vireo_directory_root_worker_t *w = NULL;
    CHECK(vireo_directory_root_worker_create(NULL, &m.options, &w), VIREO_RESULT_INVALID_ARGUMENT);
    for (unsigned i = 0; i < 7; ++i) {
        vireo_directory_root_worker_options_t o = m.options;
        switch (i) {
            case 0:
                o.execution.root_operation = 0;
                break;
            case 1:
                o.max_memory_bytes = 0;
                break;
            case 2:
                o.completion_allocation_budget = 0;
                break;
            case 3:
                o.max_memory_bytes = 1;
                break;
            case 4:
                o.max_memory_bytes = 67108865;
                break;
            case 5:
                o.execution.pool_timeout_ms = 60001;
                break;
            default:
                o.completion_allocation_budget = VIREO_COMPLETION_MAX_ALLOCATION_BYTES + 1;
                break;
        }
        CHECK(vireo_directory_root_worker_create(&m.resources, &o, &w),
              i < 3 ? VIREO_RESULT_INVALID_ARGUMENT : VIREO_RESULT_RANGE);
        assert(!w);
    }
    w = worker(&m);
    vireo_task_t *t = make_task(100, NULL);
    foreign_t f = {w, t};
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, foreign_call, &f));
    assert(!pthread_join(thread, NULL));
    vireo_directory_root_worker_report_t r;
    CHECK(vireo_directory_root_worker_run(w, NULL, &r), VIREO_RESULT_INVALID_ARGUMENT);
    assert(!r.attempted);
    CHECK(vireo_directory_root_worker_run(w, t, &r), VIREO_OK);
    outcome(&m, VIREO_OK, VIREO_STATUS_OK);
    vireo_directory_root_worker_cleanup_report_t c;
    CHECK(vireo_directory_root_worker_destroy(&w, &c), VIREO_OK);
    CHECK(vireo_directory_root_worker_destroy(&w, &c), VIREO_OK);
    CHECK(vireo_task_destroy(&t), VIREO_OK);
    for (unsigned i = 0; i < 3; ++i) {
        w = worker(&m);
        vireo_task_metadata_t md = metadata();
        unsigned char bytes[56] = {0};
        if (i == 0)
            md.operation = 401;
        if (i == 1)
            md.route.request_sequence = 2;
        CHECK(vireo_task_create_copy(md, bytes, i == 2 ? 0 : 56, 4096, &t), VIREO_OK);
        CHECK(vireo_directory_root_worker_run(w, t, &r), VIREO_RESULT_PROTOCOL);
        assert(!r.task_validated && !r.attach_called && !r.publish_called);
        CHECK(vireo_directory_root_worker_run(w, t, &r), VIREO_RESULT_BUSY);
        CHECK(vireo_task_destroy(&t), VIREO_OK);
        CHECK(vireo_directory_root_worker_destroy(&w, &c), VIREO_OK);
    }
    queue_teardown(&m.resources.queue, &m.resources.notifier);
}
int main(void) {
    int old_state = 0;
    assert(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state));
    failures();
    consumed_destroy();
    invalid();
    printf(
        "PASS directory_root_worker: %zu boundary calls; 19 run scenarios plus 2 consumed-destroy "
        "cases, affinity, "
        "permanent attempt, original-thread recovery, cleanup gate and error priority\n",
        checks);
    return 0;
}
