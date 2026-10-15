/*
 * PROJECT : VIREO
 * FILE    : test_notifier_loop_registration.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 真实 eventfd READ、原 handle 借用、故障保持及注销配对
 */
#define _GNU_SOURCE
#include <vireo/net/notifier_loop.h>
#include "notifier_loop_internal.h"
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); exit(1); } } while (0)
#define EXPECT(call, expected) do { errno = EDOM; CHECK((call) == (expected)); CHECK(errno == EDOM); } while (0)
_Static_assert(VIREO_NOTIFIER_LOOP_NONE == 0 && VIREO_NOTIFIER_LOOP_INSPECT_NOTIFIER == 1 &&
    VIREO_NOTIFIER_LOOP_REGISTER == 2 && VIREO_NOTIFIER_LOOP_UNREGISTER == 3, "independent adapter stages");

/** 测试独占 owner，handle 是数值身份，资源通过公开合同访问。 */
typedef struct fixture {
    vireo_event_loop_t *loop; /**< 主要 loop owner，cleanup 配对 destroy。 */
    vireo_event_loop_t *other; /**< 独立拥有域，测试跨域拒绝。 */
    vireo_notifier_t *notifier; /**< fd 唯一 owner，全部注册借用后销毁。 */
    vireo_event_loop_handle_t handle; /**< 主注册数值身份，DEL 后清零。 */
} fixture_t;

/** 单 Reactor 回调记录；资源短借，handle 副本不保活。 */
typedef struct callback_context {
    vireo_event_loop_t *loop; /**< 预期的存活 loop 借用。 */
    vireo_notifier_t *notifier; /**< 只用公开 consume 的原对象借用。 */
    vireo_event_loop_handle_t handle; /**< 预期原完整身份，自注销时清零。 */
    int fd; /**< 原公开观察的 fd 数值，仅比较，不 close/直接 I/O。 */
    size_t calls; /**< 本组实际回调次数。 */
    bool consume; /**< caller 回调是否公开消费提示，库注册不代做。 */
    bool self_unregister; /**< caller 回调是否显式自注销。 */
    uint64_t count; /**< 原 consume 输出，未消费时初始零。 */
    vireo_result_t result; /**< caller 的诊断值，void callback 不传播它。 */
} callback_context_t;

static bool equal_handle(vireo_event_loop_handle_t a, vireo_event_loop_handle_t b) {
    return a.loop_id == b.loop_id && a.token == b.token;
}

static size_t fd_count(void) {
    DIR *directory = opendir("/proc/self/fd"); CHECK(directory != NULL);
    int const own = dirfd(directory); size_t n = 0; struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char *end; long const fd = strtol(entry->d_name, &end, 10);
        CHECK(*end == '\0'); if (fd != own) ++n;
    }
    CHECK(closedir(directory) == 0); return n;
}

static vireo_event_loop_t *loop_create(size_t capacity) {
    vireo_event_loop_t *loop = NULL;
    vireo_event_loop_options_t const options = {4, VIREO_EVENT_LOOP_MAX_MEMORY, capacity};
    EXPECT(vireo_event_loop_create(&options, &loop, NULL), VIREO_OK); return loop;
}

static void setup(fixture_t *f, size_t capacity) {
    *f = (fixture_t){0};
    vireo_notifier_options_t const options = {4096};
    EXPECT(vireo_notifier_create(&options, &f->notifier, NULL), VIREO_OK);
    f->loop = loop_create(capacity); f->other = loop_create(1);
}

static void cleanup(fixture_t *f) {
    if (f->handle.loop_id != 0 || f->handle.token != 0)
        EXPECT(vireo_notifier_loop_unregister(f->loop, &f->handle, NULL), VIREO_OK);
    EXPECT(vireo_event_loop_destroy(&f->loop, NULL), VIREO_OK);
    EXPECT(vireo_event_loop_destroy(&f->other, NULL), VIREO_OK);
    EXPECT(vireo_notifier_destroy(&f->notifier, NULL), VIREO_OK);
}

static void observe(vireo_event_loop_t *loop, vireo_event_loop_handle_t handle,
    int fd, uint32_t events, void *context) {
    CHECK((events & VIREO_EPOLL_EVENT_READ) != 0 && (events & VIREO_EPOLL_EVENT_WRITE) == 0);
    if (context != NULL) {
        callback_context_t *c = context;
        CHECK(c->loop == loop && c->fd == fd && equal_handle(c->handle, handle)); ++c->calls;
        if (c->consume) EXPECT(vireo_notifier_consume(c->notifier, &c->count, NULL), VIREO_OK);
        if (c->self_unregister) {
            vireo_notifier_loop_error_t error;
            EXPECT(vireo_notifier_loop_unregister(loop, &c->handle, &error), VIREO_OK);
            c->result = VIREO_OK;
        } else c->result = VIREO_RESULT_IO; /* caller 保存的诊断，不是 void 返回码。 */
    }
    errno = ENOSPC;
}

static callback_context_t context_make(fixture_t *f) {
    vireo_notifier_info_t info; EXPECT(vireo_notifier_inspect(f->notifier, &info), VIREO_OK);
    return (callback_context_t){.loop = f->loop, .notifier = f->notifier, .fd = info.fd};
}

static void error_zero(vireo_notifier_loop_error_t error) {
    CHECK(error.stage == VIREO_NOTIFIER_LOOP_NONE && error.loop_error.stage == VIREO_EVENT_LOOP_STAGE_NONE &&
        error.loop_error.system_errno == 0 && error.loop_error.epoll_error.stage == VIREO_EPOLL_STAGE_NONE &&
        error.loop_error.epoll_error.system_errno == 0);
}

static void register_good(fixture_t *f, callback_context_t *context) {
    vireo_notifier_loop_error_t error; memset(&error, 0xa5, sizeof error);
    EXPECT(vireo_notifier_loop_register(f->loop, f->notifier, observe, context, &f->handle, &error), VIREO_OK);
    CHECK(f->handle.loop_id != 0 && f->handle.token != 0); error_zero(error);
    if (context != NULL) context->handle = f->handle;
}

static void notify(vireo_notifier_t *notifier) {
    vireo_notifier_notify_outcome_t outcome;
    EXPECT(vireo_notifier_notify(notifier, &outcome, NULL), VIREO_OK);
    CHECK(outcome == VIREO_NOTIFIER_NOTIFY_INCREMENTED);
}

static vireo_event_loop_run_info_t run(vireo_event_loop_t *loop, int timeout_ms) {
    vireo_event_loop_run_info_t info;
    EXPECT(vireo_event_loop_run_once(loop, timeout_ms, &info, NULL), VIREO_OK); return info;
}

static void registered_count(vireo_event_loop_t *loop, size_t count) {
    vireo_event_loop_info_t info; EXPECT(vireo_event_loop_inspect(loop, &info), VIREO_OK);
    CHECK(info.registered_count == count && info.available_count + count == info.registration_capacity);
}

static void real_registration_binding(void) {
    fixture_t f; setup(&f, 1); callback_context_t c = context_make(&f); register_good(&f, &c);
    vireo_event_loop_registration_t binding;
    EXPECT(vireo_event_loop_registration_inspect(f.loop, f.handle, &binding), VIREO_OK);
    CHECK(binding.fd == c.fd && binding.interests == VIREO_EPOLL_INTEREST_READ && binding.callback == observe && binding.context == &c);
    registered_count(f.loop, 1); CHECK(c.calls == 0); cleanup(&f);
}

static void real_read_lt_and_consume(void) {
    fixture_t f; setup(&f, 1); callback_context_t c = context_make(&f); register_good(&f, &c);
    CHECK(run(f.loop, 0).dispatched_count == 0);
    for (unsigned i = 0; i < 3; ++i) notify(f.notifier);
    CHECK(run(f.loop, 0).dispatched_count == 1 && c.calls == 1 && c.count == 0);
    CHECK(run(f.loop, 0).dispatched_count == 1 && c.calls == 2 && c.count == 0);
    c.consume = true;
    CHECK(run(f.loop, 0).dispatched_count == 1 && c.calls == 3 && c.count == 3);
    CHECK(run(f.loop, 0).dispatched_count == 0 && c.calls == 3); cleanup(&f);
}

static void unregister_preserves_notifier(void) {
    fixture_t f; setup(&f, 1); register_good(&f, NULL); notify(f.notifier);
    vireo_notifier_loop_error_t error;
    EXPECT(vireo_notifier_loop_unregister(f.loop, &f.handle, &error), VIREO_OK); error_zero(error);
    CHECK(f.handle.loop_id == 0 && f.handle.token == 0 && run(f.loop, 0).dispatched_count == 0);
    uint64_t count; EXPECT(vireo_notifier_consume(f.notifier, &count, NULL), VIREO_OK); CHECK(count == 1);
    notify(f.notifier); EXPECT(vireo_notifier_consume(f.notifier, &count, NULL), VIREO_OK); CHECK(count == 1);
    registered_count(f.loop, 0); cleanup(&f);
}

static void reregister_and_old_identity(void) {
    fixture_t f; setup(&f, 1); register_good(&f, NULL); vireo_event_loop_handle_t old = f.handle;
    EXPECT(vireo_notifier_loop_unregister(f.loop, &f.handle, NULL), VIREO_OK); register_good(&f, NULL);
    CHECK(!equal_handle(old, f.handle)); vireo_event_loop_handle_t const before = old;
    vireo_notifier_loop_error_t error; EXPECT(vireo_notifier_loop_unregister(f.loop, &old, &error), VIREO_RESULT_NOT_FOUND);
    CHECK(equal_handle(old, before) && error.stage == VIREO_NOTIFIER_LOOP_UNREGISTER);
    registered_count(f.loop, 1); cleanup(&f);
}

static void nullable_context_and_error(void) {
    fixture_t f; setup(&f, 1);
    EXPECT(vireo_notifier_loop_register(f.loop, f.notifier, observe, NULL, &f.handle, NULL), VIREO_OK);
    notify(f.notifier); CHECK(run(f.loop, 0).dispatched_count == 1);
    EXPECT(vireo_notifier_loop_unregister(f.loop, &f.handle, NULL), VIREO_OK); cleanup(&f);
}

static void basic_register_priority(void) {
    fixture_t f; setup(&f, 1);
    for (unsigned i = 0; i < 7; ++i) {
        vireo_event_loop_handle_t output = {0};
        if (i == 4) output.loop_id = 1;
        if (i == 5) output.token = 1;
        if (i == 6) output = (vireo_event_loop_handle_t){1, 1};
        vireo_event_loop_handle_t const before = output;
        vireo_notifier_loop_error_t error; memset(&error, 0xa5, sizeof error);
        EXPECT(vireo_notifier_loop_register(i == 0 ? NULL : f.loop, i == 1 ? NULL : f.notifier,
            i == 2 ? NULL : observe, NULL, i == 3 ? NULL : &output, &error), VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(equal_handle(output, before)); error_zero(error); registered_count(f.loop, 0);
    }
    cleanup(&f);
}

static void basic_unregister_priority(void) {
    fixture_t f; setup(&f, 1); register_good(&f, NULL);
    for (unsigned i = 0; i < 2; ++i) {
        vireo_event_loop_handle_t const before = f.handle; vireo_notifier_loop_error_t error;
        memset(&error, 0xa5, sizeof error);
        EXPECT(vireo_notifier_loop_unregister(i == 0 ? NULL : f.loop, i == 1 ? NULL : &f.handle, &error), VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(equal_handle(before, f.handle)); error_zero(error); registered_count(f.loop, 1);
    }
    cleanup(&f);
}

static void duplicate_fd_rejected(void) {
    fixture_t f; setup(&f, 2); register_good(&f, NULL); vireo_event_loop_handle_t duplicate = {0};
    vireo_notifier_loop_error_t error;
    EXPECT(vireo_notifier_loop_register(f.loop, f.notifier, observe, NULL, &duplicate, &error), VIREO_RESULT_BUSY);
    CHECK(duplicate.loop_id == 0 && duplicate.token == 0 && error.stage == VIREO_NOTIFIER_LOOP_REGISTER);
    registered_count(f.loop, 1); cleanup(&f);
}

static void capacity_rejected(void) {
    fixture_t f; setup(&f, 1); register_good(&f, NULL);
    vireo_notifier_t *another = NULL; vireo_notifier_options_t const options = {4096};
    EXPECT(vireo_notifier_create(&options, &another, NULL), VIREO_OK);
    vireo_event_loop_handle_t output = {0}; vireo_notifier_loop_error_t error;
    EXPECT(vireo_notifier_loop_register(f.loop, another, observe, NULL, &output, &error), VIREO_RESULT_BUSY);
    CHECK(output.loop_id == 0 && output.token == 0 && error.stage == VIREO_NOTIFIER_LOOP_REGISTER);
    registered_count(f.loop, 1); EXPECT(vireo_notifier_destroy(&another, NULL), VIREO_OK); cleanup(&f);
}

static void cross_loop_rejected(void) {
    fixture_t f; setup(&f, 1); register_good(&f, NULL); vireo_event_loop_handle_t handle = f.handle;
    vireo_notifier_loop_error_t error;
    EXPECT(vireo_notifier_loop_unregister(f.other, &handle, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(equal_handle(handle, f.handle) && error.stage == VIREO_NOTIFIER_LOOP_UNREGISTER);
    registered_count(f.loop, 1); cleanup(&f);
}

static void empty_and_malformed_identity(void) {
    fixture_t f; setup(&f, 1);
    vireo_event_loop_handle_t handles[] = {{0, 0}, {1, 0}, {0, 1}};
    for (size_t i = 0; i < 3; ++i) {
        vireo_event_loop_handle_t const before = handles[i]; vireo_notifier_loop_error_t error;
        EXPECT(vireo_notifier_loop_unregister(f.loop, &handles[i], &error), i == 0 ? VIREO_RESULT_NOT_FOUND : VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(equal_handle(handles[i], before) && error.stage == VIREO_NOTIFIER_LOOP_UNREGISTER);
    }
    cleanup(&f);
}

static void stopped_loop_not_restarted(void) {
    fixture_t f; setup(&f, 1); EXPECT(vireo_event_loop_request_stop(f.loop, NULL), VIREO_OK);
    callback_context_t c = context_make(&f); register_good(&f, &c); notify(f.notifier);
    vireo_event_loop_run_info_t const info = run(f.loop, 0);
    CHECK(info.ready_count == 0 && info.dispatched_count == 0 && c.calls == 0);
    c.consume = true; uint64_t count; EXPECT(vireo_notifier_consume(f.notifier, &count, NULL), VIREO_OK); CHECK(count == 1);
    registered_count(f.loop, 1); cleanup(&f);
}

static void self_unregister_callback(void) {
    fixture_t f; setup(&f, 1); callback_context_t c = context_make(&f);
    c.self_unregister = true; c.consume = true; register_good(&f, &c); notify(f.notifier);
    CHECK(run(f.loop, 0).dispatched_count == 1 && c.calls == 1 && c.count == 1 && c.result == VIREO_OK);
    CHECK(c.handle.loop_id == 0 && c.handle.token == 0); f.handle = c.handle;
    registered_count(f.loop, 0); cleanup(&f);
}

static void loop_destroy_ends_registration(void) {
    fixture_t f; setup(&f, 1); register_good(&f, NULL);
    EXPECT(vireo_event_loop_destroy(&f.loop, NULL), VIREO_OK); f.handle = (vireo_event_loop_handle_t){0};
    notify(f.notifier); uint64_t count;
    EXPECT(vireo_notifier_consume(f.notifier, &count, NULL), VIREO_OK); CHECK(count == 1); cleanup(&f);
}

static void void_callback_diagnostic(void) {
    fixture_t f; setup(&f, 1); callback_context_t c = context_make(&f); c.consume = true;
    register_good(&f, &c); notify(f.notifier);
    CHECK(run(f.loop, 0).dispatched_count == 1 && c.result == VIREO_RESULT_IO && c.count == 1);
    cleanup(&f);
}

/** 仅本适配层调用账本和模型错误，不触碰依赖布局。 */
typedef struct fault_context {
    size_t inspect_calls; /**< 本层实际调用观察 seam 次数。 */
    size_t add_calls; /**< 本层实际调用 ADD seam 次数。 */
    size_t del_calls; /**< 本层实际调用 DEL seam 次数。 */
    vireo_notifier_loop_stage_t reject; /**< 模型拒绝点，NONE 不拒绝。 */
    vireo_result_t result; /**< 模型返回类别，非真实系统报告。 */
    int cause; /**< 模型系统原因，只有 IO 时写入嵌套。 */
    vireo_event_loop_registration_t seen; /**< ADD 输入值快照，借用不延长寿命。 */
} fault_context_t;

static vireo_result_t inspect_fault(void *context, vireo_notifier_t const *notifier, vireo_notifier_info_t *info) {
    fault_context_t *f = context; ++f->inspect_calls; errno = EFAULT;
    if (f->reject == VIREO_NOTIFIER_LOOP_INSPECT_NOTIFIER) return f->result;
    return vireo_notifier_inspect(notifier, info);
}

static vireo_result_t add_fault(void *context, vireo_event_loop_t *loop,
    vireo_event_loop_registration_t const *registration, vireo_event_loop_handle_t *handle,
    vireo_event_loop_error_t *error) {
    fault_context_t *f = context; ++f->add_calls; f->seen = *registration; errno = EFAULT;
    if (f->reject != VIREO_NOTIFIER_LOOP_REGISTER) return vireo_event_loop_add(loop, registration, handle, error);
    *error = (vireo_event_loop_error_t){0};
    if (f->result == VIREO_RESULT_IO) *error = (vireo_event_loop_error_t){
        VIREO_EVENT_LOOP_STAGE_ADD, {VIREO_EPOLL_STAGE_ADD, f->cause}, 0};
    return f->result;
}

static vireo_result_t del_fault(void *context, vireo_event_loop_t *loop,
    vireo_event_loop_handle_t *handle, vireo_event_loop_error_t *error) {
    fault_context_t *f = context; ++f->del_calls; errno = EFAULT;
    if (f->reject != VIREO_NOTIFIER_LOOP_UNREGISTER) return vireo_event_loop_del(loop, handle, error);
    *error = (vireo_event_loop_error_t){VIREO_EVENT_LOOP_STAGE_DEL, {VIREO_EPOLL_STAGE_DEL, f->cause}, 0};
    return f->result;
}
static vireo_notifier_loop_ops_t const fault_ops = {inspect_fault, add_fault, del_fault};

static void inspect_model_rejected(void) {
    fixture_t f; setup(&f, 1); fault_context_t model = {.reject = VIREO_NOTIFIER_LOOP_INSPECT_NOTIFIER, .result = VIREO_RESULT_INVALID_ARGUMENT};
    vireo_notifier_loop_error_t error;
    EXPECT(vireo_notifier_loop_register_with_ops(f.loop, f.notifier, observe, NULL, &f.handle,
        &error, &fault_ops, &model), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(error.stage == VIREO_NOTIFIER_LOOP_INSPECT_NOTIFIER && error.loop_error.stage == 0 &&
        model.inspect_calls == 1 && model.add_calls == 0 && f.handle.loop_id == 0 && f.handle.token == 0);
    registered_count(f.loop, 0); cleanup(&f);
}

static void add_model_failures(void) {
    fixture_t f; setup(&f, 1); callback_context_t c = context_make(&f);
    vireo_result_t const results[] = {VIREO_RESULT_IO, VIREO_RESULT_BUSY, VIREO_RESULT_OVERFLOW};
    for (size_t i = 0; i < 3; ++i) {
        fault_context_t model = {.reject = VIREO_NOTIFIER_LOOP_REGISTER, .result = results[i], .cause = EINTR};
        vireo_notifier_loop_error_t error; memset(&error, 0xa5, sizeof error);
        EXPECT(vireo_notifier_loop_register_with_ops(f.loop, f.notifier, observe, &c, &f.handle,
            &error, &fault_ops, &model), results[i]);
        CHECK(error.stage == VIREO_NOTIFIER_LOOP_REGISTER && model.inspect_calls == 1 && model.add_calls == 1 &&
            model.del_calls == 0 && model.seen.fd == c.fd && model.seen.interests == VIREO_EPOLL_INTEREST_READ &&
            model.seen.callback == observe && model.seen.context == &c && f.handle.loop_id == 0 && f.handle.token == 0);
        CHECK(error.loop_error.epoll_error.system_errno == (i == 0 ? EINTR : 0)); registered_count(f.loop, 0);
    }
    register_good(&f, &c); cleanup(&f);
}

static void del_model_borrow_kept(void) {
    fixture_t f; setup(&f, 1); callback_context_t c = context_make(&f); register_good(&f, &c);
    vireo_event_loop_handle_t const before = f.handle;
    fault_context_t model = {.reject = VIREO_NOTIFIER_LOOP_UNREGISTER, .result = VIREO_RESULT_IO, .cause = EINTR};
    vireo_notifier_loop_error_t error;
    EXPECT(vireo_notifier_loop_unregister_with_ops(f.loop, &f.handle, &error, &fault_ops, &model), VIREO_RESULT_IO);
    CHECK(equal_handle(f.handle, before) && model.del_calls == 1 && model.inspect_calls == 0 && model.add_calls == 0 &&
        error.stage == VIREO_NOTIFIER_LOOP_UNREGISTER && error.loop_error.stage == VIREO_EVENT_LOOP_STAGE_DEL &&
        error.loop_error.epoll_error.stage == VIREO_EPOLL_STAGE_DEL && error.loop_error.epoll_error.system_errno == EINTR);
    notify(f.notifier); CHECK(run(f.loop, 0).dispatched_count == 1 && c.calls == 1); registered_count(f.loop, 1);
    cleanup(&f);
}

static void invalid_ops_basic_precedence(void) {
    fixture_t f; setup(&f, 1); fault_context_t model = {0};
    for (unsigned i = 0; i < 4; ++i) {
        vireo_notifier_loop_ops_t ops = fault_ops;
        if (i == 1) ops.inspect = NULL;
        if (i == 2) ops.add = NULL;
        vireo_event_loop_handle_t handle = {0}; vireo_notifier_loop_error_t error;
        EXPECT(vireo_notifier_loop_register_with_ops(i == 3 ? NULL : f.loop, f.notifier, observe, NULL,
            &handle, &error, i == 0 ? NULL : &ops, &model), VIREO_RESULT_INVALID_ARGUMENT);
        error_zero(error); CHECK(handle.loop_id == 0 && handle.token == 0 && model.inspect_calls == 0 && model.add_calls == 0);
    }
    vireo_notifier_loop_ops_t ops = fault_ops; ops.del = NULL;
    vireo_notifier_loop_error_t error;
    EXPECT(vireo_notifier_loop_unregister_with_ops(f.loop, &f.handle, &error, &ops, &model), VIREO_RESULT_INVALID_ARGUMENT);
    error_zero(error); cleanup(&f);
}

/** 只有 notifier 被跨线程发布，join 后读取两个输出。 */
typedef struct producer_context {
    vireo_notifier_t *notifier; /**< 已创建稳定对象借用，到 join 后结束。 */
    vireo_result_t result; /**< worker notify 原返回，仅 join 后读取。 */
    vireo_notifier_notify_outcome_t outcome; /**< worker 独立输出，仅 join 后读取。 */
} producer_context_t;
static void *produce(void *context) {
    producer_context_t *p = context; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    p->result = vireo_notifier_notify(p->notifier, &p->outcome, NULL); return NULL;
}

static void producer_notify_reactor_dispatch(void) {
    fixture_t f; setup(&f, 1); callback_context_t c = context_make(&f); c.consume = true; register_good(&f, &c);
    producer_context_t p = {.notifier = f.notifier}; pthread_t thread;
    CHECK(pthread_create(&thread, NULL, produce, &p) == 0);
    vireo_event_loop_run_info_t const info = run(f.loop, 1000);
    CHECK(pthread_join(thread, NULL) == 0 && p.result == VIREO_OK && p.outcome == VIREO_NOTIFIER_NOTIFY_INCREMENTED);
    CHECK(info.dispatched_count == 1 && c.calls == 1 && c.count == 1); cleanup(&f);
}

static void fd_zero_child(void) {
    /* 仅隔离 child 的 stdin 数值，为 notifier 取得合法 0；不关闭借用 notifier fd。 */
    if (close(STDIN_FILENO) != 0) CHECK(errno == EBADF);
    fixture_t f; setup(&f, 1); callback_context_t c = context_make(&f); CHECK(c.fd == 0);
    c.consume = true; register_good(&f, &c); notify(f.notifier);
    CHECK(run(f.loop, 0).dispatched_count == 1 && c.count == 1); cleanup(&f);
}

static void fd_zero(void) {
    pid_t const child = fork(); CHECK(child >= 0);
    if (child == 0) { execl("/proc/self/exe", "vireo_notifier_loop_registration_test", "--fd-zero", (char *)NULL); _Exit(127); }
    int status; CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(int argc, char **argv) {
    int previous; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    if (argc == 2 && strcmp(argv[1], "--fd-zero") == 0) { fd_zero_child(); CHECK(pthread_setcancelstate(previous, NULL) == 0); return 0; }
    struct test_case { char const *name; void (*run)(void); } const cases[] = {
        {"real_registration_binding", real_registration_binding}, {"real_read_lt_and_consume", real_read_lt_and_consume},
        {"unregister_preserves_notifier", unregister_preserves_notifier}, {"reregister_and_old_identity", reregister_and_old_identity},
        {"nullable_context_and_error", nullable_context_and_error}, {"basic_register_priority", basic_register_priority},
        {"basic_unregister_priority", basic_unregister_priority}, {"duplicate_fd_rejected", duplicate_fd_rejected},
        {"capacity_rejected", capacity_rejected}, {"cross_loop_rejected", cross_loop_rejected},
        {"empty_and_malformed_identity", empty_and_malformed_identity}, {"stopped_loop_not_restarted", stopped_loop_not_restarted},
        {"self_unregister_callback", self_unregister_callback}, {"loop_destroy_ends_registration", loop_destroy_ends_registration},
        {"void_callback_diagnostic", void_callback_diagnostic}, {"inspect_model_rejected", inspect_model_rejected},
        {"add_model_failures", add_model_failures}, {"del_model_borrow_kept", del_model_borrow_kept},
        {"invalid_ops_basic_precedence", invalid_ops_basic_precedence}, {"producer_notify_reactor_dispatch", producer_notify_reactor_dispatch},
        {"fd_zero", fd_zero}
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        size_t const before = fd_count(); cases[i].run(); CHECK(fd_count() == before); printf("PASS %s\n", cases[i].name);
    }
    printf("notifier loop registration: %zu groups passed\n", sizeof cases / sizeof cases[0]);
    CHECK(pthread_setcancelstate(previous, NULL) == 0); return 0;
}
