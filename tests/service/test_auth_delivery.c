/* PROJECT : VIREO
 * FILE : test_auth_delivery.c
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : 采样失败原子性、固定内部编码及回投所有权边界。
 */
#define _POSIX_C_SOURCE 200809L
#include "auth_task_test_support.h"
#include <vireo/service/auth_task.h>
static vireo_auth_task_options_t const context_registry={100,101,5000,102,103};
#include "auth_task_context_internal.h"
#include "auth_completion_internal.h"
#include <pthread.h>

static vireo_task_t *make_task(bool login, vireo_task_metadata_t *metadata)
{
    unsigned char wire[156]; size_t n = frame(wire, login, 7, false);
    *metadata = task_context(7, 1, login).metadata;
    vireo_task_t *task = NULL;
    CHECK(vireo_task_create_copy(*metadata, wire, n, 4096, &task), VIREO_OK);
    CHECK(vireo_secure_clear(wire, sizeof(wire)), VIREO_OK);
    return task;
}

typedef struct samples {
    unsigned step;
    int random_rc, utc_rc;
    bool zero;
    struct timespec utc;
    uint64_t monotonic;
    vireo_result_t clock_rc;
} samples_t;
static int random_sample(void *p, unsigned char out[16])
{
    samples_t *s = p; assert(s->step++ == 0); memset(out, s->zero ? 0 : 17, 16); return s->random_rc;
}
static int utc_sample(void *p, struct timespec *out)
{
    samples_t *s = p; assert(s->step++ == 1); *out = s->utc; errno = EIO; return s->utc_rc;
}
static vireo_result_t mono_sample(void *p, vireo_monotonic_ns_t *out, vireo_clock_error_t *error)
{
    samples_t *s = p; assert(s->step++ == 2); (void)error;
    if (s->clock_rc == VIREO_OK) *out = s->monotonic;
    return s->clock_rc;
}
static void sampling(void)
{
    vireo_task_metadata_t metadata; vireo_task_t *task = make_task(true, &metadata);
    samples_t s = {0, 1, 0, false, {2, 123999999}, 9999, VIREO_OK};
    vireo_auth_context_ops_t ops = {random_sample, utc_sample, mono_sample, &s};
    vireo_auth_task_context_t output, before; memset(&before, 0xa5, sizeof(before)); output = before;
    vireo_auth_context_error_t error;
    CHECK(vireo_auth_task_context_with(task, 1000, 60000, &context_registry, &output, &error, &ops), VIREO_OK);
    assert(s.step == 3 && error.stage == VIREO_AUTH_CONTEXT_NONE && output.occurred_at_ms == 2123 &&
        output.expires_at_ms == 62123 && output.latency_us == 8 && output.now_ns == 9999 && output.request_id[0] == 17);
    assert(output.metadata.operation == metadata.operation);
    for (unsigned i = 0; i < 12; ++i) {
        s = (samples_t){0, 1, 0, false, {2, 123999999}, 9999, VIREO_OK}; output = before;
        vireo_result_t expected = VIREO_RESULT_IO; vireo_auth_context_stage_t stage = VIREO_AUTH_CONTEXT_RANDOM;
        uint64_t lifetime = 60000, received = 1000;
        switch (i) {
        case 0: s.random_rc = 0; break;
        case 1: s.random_rc = -1; break;
        case 2: s.zero = true; break;
        case 3: s.utc_rc = -1; stage = VIREO_AUTH_CONTEXT_UTC; break;
        case 4: s.utc_rc = 1; expected = VIREO_RESULT_INTERNAL; stage = VIREO_AUTH_CONTEXT_UTC; break;
        case 5: s.utc.tv_sec = -1; expected = VIREO_RESULT_INTERNAL; stage = VIREO_AUTH_CONTEXT_UTC; break;
        case 6: s.utc.tv_nsec = -1; expected = VIREO_RESULT_INTERNAL; stage = VIREO_AUTH_CONTEXT_UTC; break;
        case 7: s.utc.tv_nsec = 1000000000; expected = VIREO_RESULT_INTERNAL; stage = VIREO_AUTH_CONTEXT_UTC; break;
        case 8: s.utc.tv_sec = (time_t)INT64_MAX; expected = VIREO_RESULT_OVERFLOW; stage = VIREO_AUTH_CONTEXT_UTC; break;
        case 9: lifetime = UINT64_MAX; expected = VIREO_RESULT_OVERFLOW; stage = VIREO_AUTH_CONTEXT_EXPIRY; break;
        case 10: s.clock_rc = VIREO_RESULT_IO; stage = VIREO_AUTH_CONTEXT_MONOTONIC; break;
        default: received = 10000; expected = VIREO_RESULT_RANGE; stage = VIREO_AUTH_CONTEXT_LATENCY; break;
        }
        CHECK(vireo_auth_task_context_with(task, received, lifetime, &context_registry, &output, &error, &ops), expected);
        assert(!memcmp(&output, &before, sizeof(output)) && error.stage == stage);
        assert(s.step == (i < 3 ? 1u : i < 10 ? 2u : 3u));
        assert(error.system_errno == (i == 3 ? EIO : 0));
    }
    s.step = 0;
    CHECK(vireo_auth_task_context_with(task, 0, 0, &context_registry, &output, &error, &ops), VIREO_RESULT_RANGE); assert(s.step == 0);
    CHECK(vireo_auth_task_context_with(NULL, 0, 1, &context_registry, &output, &error, &ops), VIREO_RESULT_INVALID_ARGUMENT);
    assert(!memcmp(&output, &before, sizeof(output)));
    CHECK(vireo_task_destroy(&task), VIREO_OK);
    task = make_task(false, &metadata);
    s = (samples_t){0, 1, 0, false, {0, 999999}, 0, VIREO_OK};
    CHECK(vireo_auth_task_context_with(task, 0, UINT64_MAX, &context_registry, &output, NULL, &ops), VIREO_OK);
    assert(output.occurred_at_ms == 0 && output.expires_at_ms == 0 && output.latency_us == 0);
    vireo_monotonic_ns_t accepted = 0; CHECK(vireo_clock_monotonic_now(&accepted, NULL), VIREO_OK);
    CHECK(vireo_auth_task_context_capture(task, accepted, 0, &context_registry, &output, &error), VIREO_OK);
    assert(output.now_ns >= accepted && output.occurred_at_ms > 0);
    CHECK(vireo_task_destroy(&task), VIREO_OK);
    CHECK(vireo_task_create_copy(metadata, NULL, 0, 4096, &task), VIREO_OK);
    s.step = 0; output = before;
    CHECK(vireo_auth_task_context_with(task, 0, 1, &context_registry, &output, &error, &ops), VIREO_RESULT_PROTOCOL);
    assert(s.step == 0 && error.stage == VIREO_AUTH_CONTEXT_DECODE && !memcmp(&output, &before, sizeof(output)));
    CHECK(vireo_task_destroy(&task), VIREO_OK);
}

static vireo_auth_task_result_t result_for(vireo_task_metadata_t metadata, bool login)
{
    vireo_auth_task_result_t r = {.stage = VIREO_AUTH_TASK_SERVICE, .result = VIREO_OK,
        .metadata = metadata, .command = login ? VIREO_COMMAND_LOGIN : VIREO_COMMAND_REGISTER};
    if (login) {
        r.login.transaction.commit = VIREO_MYSQL_LOGIN_COMMITTED;
        r.login.user_id = 0x0102030405060708; r.login.transaction.session_id = 3;
        r.login.transaction.audit_id = 4; r.login.issued_at_ms = 5; r.login.expires_at_ms = 6;
        for (size_t i = 0; i < 32; ++i) r.login.token.bytes[i] = (unsigned char)i;
    } else {
        r.registration.commit = VIREO_MYSQL_REGISTRATION_COMMITTED;
        r.registration.user_id = 2; r.registration.root_node_id = 3; r.registration.audit_id = 4;
    }
    return r;
}
static void failure_projection(void)
{
    vireo_task_metadata_t metadata;vireo_task_t *task=make_task(true,&metadata);
    vireo_auth_task_context_t context={.metadata=metadata,.request_id={7},.occurred_at_ms=99,.latency_us=13};
    vireo_auth_task_result_t r={.stage=VIREO_AUTH_TASK_SERVICE,.metadata=metadata,.command=VIREO_COMMAND_SESSION_RESUME,
        .result=VIREO_OK,.resume_report={.valid=true},.resume_identity={.user_id=2,.session_id=3,.issued_at_ms=1,.expires_at_ms=99}};
    vireo_auth_failure_event_t event,old;memset(&old,0xa5,sizeof old);event=old;
    CHECK(vireo_auth_failure_event_from_task(&r,&context,&event),VIREO_RESULT_NOT_FOUND);
    assert(!memcmp(&event,&old,sizeof old));
    r.resume_report.valid=false;r.resume_identity=(vireo_mysql_session_identity_t){0};r.result=VIREO_RESULT_NOT_FOUND;
    CHECK(vireo_auth_failure_event_from_task(&r,&context,&event),VIREO_OK);assert(event.action==4 && event.status==1104);
    r.command=VIREO_COMMAND_LOGOUT;r.logout_target=(vireo_auth_logout_identity_t){2,3};
    CHECK(vireo_auth_failure_event_from_task(&r,&context,&event),VIREO_OK);assert(event.action==3 && event.status==1104);
    r.logout_report.commit=VIREO_MYSQL_LOGOUT_UNKNOWN;r.result=VIREO_RESULT_DATABASE;event=old;
    CHECK(vireo_auth_failure_event_from_task(&r,&context,&event),VIREO_RESULT_NOT_FOUND);assert(!memcmp(&event,&old,sizeof old));
    r.logout_report=(vireo_mysql_logout_report_t){.commit=VIREO_MYSQL_LOGOUT_COMMITTED,.session_id=3,.audit_id=4,.revoked_at_ms=33};
    CHECK(vireo_auth_failure_event_from_task(&r,&context,&event),VIREO_RESULT_NOT_FOUND);
    r=(vireo_auth_task_result_t){.stage=VIREO_AUTH_TASK_SERVICE,.metadata=metadata,.command=VIREO_COMMAND_REGISTER,
        .result=VIREO_RESULT_DATABASE,.registration={.conflict=VIREO_MYSQL_REGISTRATION_USERNAME_CONFLICT}};
    CHECK(vireo_auth_failure_event_from_task(&r,&context,&event),VIREO_OK);assert(event.action==1 && event.status==VIREO_STATUS_USER_EXISTS);
    CHECK(vireo_task_destroy(&task),VIREO_OK);
}
static unsigned injected_calls;
/* 在真实交接后模拟通知错误；只替换本模块公开依赖，不触碰线程私有状态。 */
static vireo_result_t transferred_io(vireo_task_t const *task, vireo_result_t result,
    vireo_status_t status, void const *data, size_t size, size_t budget,
    vireo_completion_queue_t *queue, vireo_notifier_t *notifier,
    vireo_completion_t **remaining, vireo_completion_publish_report_t *report)
{
    ++injected_calls;
    CHECK(vireo_completion_copy_wait_publish(task, result, status, data, size, budget, queue, notifier, remaining, report), VIREO_OK);
    report->notify_result = VIREO_RESULT_IO; report->stage = VIREO_COMPLETION_PUBLISH_NOTIFY;
    return VIREO_RESULT_IO;
}
static vireo_completion_t *pop(vireo_completion_queue_t *queue)
{
    vireo_completion_t *c = NULL; vireo_completion_queue_transfer_report_t report;
    CHECK(vireo_completion_queue_try_pop(queue, &c, &report), VIREO_OK); assert(report.transferred && c); return c;
}
static void publication(void)
{
    vireo_completion_queue_t *queue = NULL; vireo_notifier_t *notifier = NULL;
    vireo_completion_queue_options_t qo = {4, 65536}; vireo_notifier_options_t no = {4096};
    CHECK(vireo_completion_queue_create(&qo, &queue), VIREO_OK);
    CHECK(vireo_notifier_create(&no, &notifier, NULL), VIREO_OK);
    vireo_task_metadata_t metadata; vireo_task_t *task = make_task(true, &metadata);
    vireo_auth_task_result_t result = result_for(metadata, true), before = result;
    vireo_auth_completion_publish_report_t report; vireo_completion_t *remaining = NULL;
    CHECK(vireo_auth_completion_publish(task, &result, 4096, queue, notifier, &remaining, &report), VIREO_RESULT_NOT_FOUND);
    assert(remaining && report.publication.completion_retained && !report.publication.notify_called);
    CHECK(vireo_completion_destroy(&remaining), VIREO_OK);
    CHECK(vireo_completion_queue_prepare_wait(queue), VIREO_OK);
    CHECK(vireo_auth_completion_publish(task, &result, 1, queue, notifier, &remaining, &report), VIREO_RESULT_RANGE);
    assert(!remaining && !report.publication.completion_created);
    CHECK(vireo_auth_completion_publish_with(task, &result, 4096, queue, notifier, &remaining, &report, transferred_io), VIREO_RESULT_IO);
    assert(injected_calls == 1 && !remaining && report.publication.completion_transferred && report.publication.notify_called);
    assert(!memcmp(&result, &before, sizeof(result)));
    vireo_completion_t *completion = pop(queue); vireo_completion_payload_view_t view;
    CHECK(vireo_completion_borrow_payload(completion, &view), VIREO_OK);
    unsigned char bytes[88]; memcpy(bytes, view.data, sizeof(bytes));
    unsigned char const golden[56] = {'V','A','C','1',1,1,0,1,
        1,2,3,4,5,6,7,8, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,3,
        0,0,0,0,0,0,0,4, 0,0,0,0,0,0,0,5, 0,0,0,0,0,0,0,6};
    assert(view.size == 88 && !memcmp(bytes, golden, sizeof(golden)) && !memcmp(bytes + 56, result.login.token.bytes, 32));
    vireo_auth_completion_outcome_t output = {0};
    CHECK(vireo_auth_completion_decode(completion, &output), VIREO_OK);
    CHECK(vireo_completion_destroy(&completion), VIREO_OK);
    CHECK(vireo_auth_task_result_clear(&result), VIREO_OK);
    assert(output.token.bytes[31] == 31 && output.user_id == before.login.user_id);
    CHECK(vireo_auth_completion_outcome_clear(&output), VIREO_OK);
    unsigned char const zero[sizeof(output)] = {0}; assert(!memcmp(&output, zero, sizeof(output)));
    /* 元数据、命令、提交事实及业务状态映射各自独立。 */
    for (unsigned i = 0; i < 9; ++i) {
        result = (vireo_auth_task_result_t){.stage = VIREO_AUTH_TASK_SERVICE, .result = VIREO_RESULT_INTERNAL,
            .metadata = metadata, .command = VIREO_COMMAND_LOGIN};
        vireo_status_t status = VIREO_STATUS_INTERNAL_ERROR;
        switch (i) {
        case 0: result.result = VIREO_RESULT_NOT_FOUND; status = VIREO_STATUS_AUTHENTICATION_FAILED; break;
        case 1: result.result = VIREO_RESULT_TIMEOUT; status = VIREO_STATUS_TIMEOUT; break;
        case 2: result.result = VIREO_RESULT_BUSY; status = VIREO_STATUS_BUSY; break;
        case 3: result.result = VIREO_RESULT_CANCELLED; status = VIREO_STATUS_UNAVAILABLE; break;
        case 4: result.stage = VIREO_AUTH_TASK_DECODE; result.result = VIREO_RESULT_PROTOCOL; status = VIREO_STATUS_BAD_REQUEST; break;
        case 5: result.login.transaction.commit = VIREO_MYSQL_LOGIN_UNKNOWN; result.result = VIREO_RESULT_DATABASE; break;
        case 6: result = before; result.result = VIREO_RESULT_DATABASE; result.login.transaction.cleanup_pending = true; status = VIREO_STATUS_OK; break;
        case 7: result = before; memset(result.login.token.bytes, 0, 32); status = VIREO_STATUS_OK; break;
        default: break;
        }
        vireo_auth_task_context_t context={.metadata=metadata,.request_id={3},.occurred_at_ms=123,.latency_us=456};
        vireo_auth_failure_event_t event,old_event;memset(&old_event,0xa5,sizeof old_event);event=old_event;
        CHECK(vireo_auth_failure_event_from_task(&result,&context,&event),
            i==5 || i==6 || i==7?VIREO_RESULT_NOT_FOUND:VIREO_OK);
        if(i==5 || i==6 || i==7) assert(!memcmp(&event,&old_event,sizeof event));
        else assert(event.action==2 && event.status==status && event.origin==VIREO_AUTH_FAILURE_WORKER &&
            event.request_id[0]==3 && event.occurred_at_ms==123 && event.latency_us==456);
        ++context.metadata.deadline_ns;event=old_event;
        CHECK(vireo_auth_failure_event_from_task(&result,&context,&event),VIREO_RESULT_INVALID_ARGUMENT);
        assert(!memcmp(&event,&old_event,sizeof event));
        CHECK(vireo_auth_completion_publish(task, &result, 4096, queue, notifier, &remaining, &report), VIREO_OK);
        completion = pop(queue); CHECK(vireo_auth_completion_decode(completion, &output), VIREO_OK);
        assert(output.metadata.suggested_status == status && output.metadata.result == result.result);
        assert(output.commit == (i == 5 ? VIREO_AUTH_COMMIT_UNKNOWN : i == 6 || i == 7 ? VIREO_AUTH_COMMITTED : VIREO_AUTH_NOT_COMMITTED));
        CHECK(vireo_completion_destroy(&completion), VIREO_OK);
        CHECK(vireo_auth_completion_outcome_clear(&output), VIREO_OK);
    }
    result = before; ++result.metadata.deadline_ns;
    CHECK(vireo_auth_completion_publish(task, &result, 4096, queue, notifier, &remaining, &report), VIREO_RESULT_INVALID_ARGUMENT);
    assert(report.result_validated && !report.task_matched && !report.publish_called && !remaining);
    result = before; result.login.expires_at_ms = 5;
    CHECK(vireo_auth_completion_publish(task, &result, 4096, queue, notifier, &remaining, &report), VIREO_RESULT_INVALID_ARGUMENT);
    assert(!report.result_validated);
    result = before; result.command = VIREO_COMMAND_REGISTER; memset(&result.login, 0, sizeof(result.login));
    result.result = VIREO_RESULT_INTERNAL;
    CHECK(vireo_auth_completion_publish(task, &result, 4096, queue, notifier, &remaining, &report), VIREO_RESULT_PROTOCOL);
    CHECK(vireo_task_destroy(&task), VIREO_OK);
    task = make_task(false, &metadata); result = result_for(metadata, false);
    for (unsigned i = 0; i < 2; ++i) {
        if (i) { memset(&result.registration, 0, sizeof(result.registration)); result.result = VIREO_RESULT_DATABASE;
            result.registration.conflict = VIREO_MYSQL_REGISTRATION_USERNAME_CONFLICT; }
        CHECK(vireo_auth_completion_publish(task, &result, 4096, queue, notifier, &remaining, &report), VIREO_OK);
        completion = pop(queue); CHECK(vireo_auth_completion_decode(completion, &output), VIREO_OK);
        assert(output.metadata.suggested_status == (i ? VIREO_STATUS_USER_EXISTS : VIREO_STATUS_OK));
        CHECK(vireo_completion_destroy(&completion), VIREO_OK);
    }
    vireo_completion_queue_close_report_t closed;
    CHECK(vireo_completion_queue_close(queue, &closed), VIREO_OK);
    CHECK(vireo_auth_completion_publish(task, &result, 4096, queue, notifier, &remaining, &report), VIREO_RESULT_CANCELLED);
    assert(remaining && !report.publication.completion_transferred && !report.publication.notify_called);
    CHECK(vireo_completion_destroy(&remaining), VIREO_OK);
    CHECK(vireo_task_destroy(&task), VIREO_OK);
    CHECK(vireo_completion_queue_destroy(&queue), VIREO_OK);
    CHECK(vireo_notifier_destroy(&notifier, NULL), VIREO_OK);
    CHECK(vireo_auth_completion_outcome_clear(&output), VIREO_OK);
    CHECK(vireo_auth_task_result_clear(&before), VIREO_OK);
    CHECK(vireo_auth_task_result_clear(&result), VIREO_OK);
    CHECK(vireo_secure_clear(bytes, sizeof(bytes)), VIREO_OK);
}
static void malformed(void)
{
    vireo_completion_metadata_t metadata;
    CHECK(vireo_completion_metadata_make(task_context(7, 1, true).metadata, VIREO_OK, VIREO_STATUS_OK, &metadata), VIREO_OK);
    unsigned char const valid[88] = {'V','A','C','1',1,1,0,1,
        0,0,0,0,0,0,0,2, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,3,
        0,0,0,0,0,0,0,4, 0,0,0,0,0,0,0,5, 0,0,0,0,0,0,0,6};
    vireo_auth_completion_outcome_t output, old; memset(&old, 0xa5, sizeof(old)); output = old;
    for (unsigned i = 0; i < 11; ++i) {
        unsigned char bytes[88]; memcpy(bytes, valid, sizeof(bytes)); size_t size = sizeof(bytes);
        switch (i) {
        case 0: size = 0; break; case 1: --size; break; case 2: bytes[0] = 'X'; break;
        case 3: bytes[4] = 255; break; case 4: bytes[6] = 1; break; case 5: bytes[7] = 3; break;
        case 6: bytes[15] = 0; break; case 7: bytes[23] = 1; break; case 8: bytes[31] = 0; break;
        case 9: bytes[39] = 0; break; default: bytes[55] = 5; break;
        }
        vireo_completion_t *completion = NULL;
        CHECK(vireo_completion_create_copy(metadata, bytes, size, 4096, &completion), VIREO_OK);
        CHECK(vireo_auth_completion_decode(completion, &output), VIREO_RESULT_PROTOCOL);
        assert(!memcmp(&output, &old, sizeof(old)));
        CHECK(vireo_completion_destroy(&completion), VIREO_OK);
    }
    CHECK(vireo_auth_completion_decode(NULL, &output), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_auth_completion_outcome_clear(NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_auth_completion_outcome_clear(&output), VIREO_OK);
    CHECK(vireo_auth_completion_outcome_clear(&old), VIREO_OK);
}
int main(void)
{
    int previous = 0; assert(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    sampling(); publication(); malformed(); failure_projection();
    assert(pthread_setcancelstate(previous, NULL) == 0);
    puts("PASS auth_delivery: sampling order/atomicity, native clocks/RNG, VAC1 golden bytes, status/commit matrix, independent tokens, transferred-error and retained-owner, malformed decoding");
    return 0;
}
