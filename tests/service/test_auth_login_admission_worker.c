/*
 * PROJECT : VIREO
 * FILE    : test_auth_login_admission_worker.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 单Reactor准入后才提交两个真实worker；拒绝不执行KDF，不接DB或客户fd。
 */
#define _POSIX_C_SOURCE 200809L
#include <vireo/service/auth_password.h>
#include <vireo/service/auth_login_admission.h>
#include <stdatomic.h>
#include <vireo/thread/thread_pool.h>
#include <assert.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static uint64_t now_ns(void)
{
    struct timespec now;
    assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

/* 真实worker可能同时领取；只重试合同允许的锁竞争，不重做准入或复制任务。 */
static void submit_task(vireo_thread_pool_t *pool, vireo_task_t **task)
{
    uint64_t const deadline = now_ns() + UINT64_C(5000000000);
    vireo_task_t *const original = *task;
    for (;;) {
        vireo_thread_pool_submit_report_t submit;
        vireo_result_t const result = vireo_thread_pool_try_submit(pool, task, &submit);
        assert(submit.queue_called);
        if (result == VIREO_OK) {
            assert(*task == NULL && submit.queue_report.transferred &&
                submit.stage == VIREO_THREAD_POOL_SUBMIT_STAGE_NONE);
            return;
        }
        assert(result == VIREO_RESULT_BUSY && *task == original &&
            !submit.queue_report.transferred &&
            submit.stage == VIREO_THREAD_POOL_SUBMIT_STAGE_SUBMIT_QUEUE &&
            submit.queue_report.stage == VIREO_TASK_QUEUE_STAGE_LOCK &&
            submit.queue_report.pthread_error == EBUSY);
        assert(now_ns() < deadline);
        struct timespec const pause = {0, 1000000};
        assert(nanosleep(&pause, NULL) == 0 || errno == EINTR);
    }
}

typedef struct worker_fixture {
    pthread_t manager; /**< 管理端身份，证明业务入口在真实worker运行。 */
    pthread_barrier_t entered; /**< 两worker均进入，防止单线程顺序跑两任务。 */
    vireo_auth_password_gate_t *gate; /**< manager独占owner，全部worker共享借用。 */
    char encoded[2][128]; /**< 每任务独占结果，join之后manager读并清理。 */
    size_t lengths[2]; /**< 各任务独占输出长度。 */
    bool done[2]; /**< 各任务完成事实，join建立可见性。 */
    atomic_uint executions; /**< 真实worker执行计数，拒绝不能增加。 */
} worker_fixture_t;

/* 不打印密码/PHC，公开inspect验证生成成本；大小写改变应正常错密。 */
static vireo_result_t execute(void *context, vireo_task_t const *task)
{
    worker_fixture_t *f = context;
    assert(pthread_equal(f->manager, pthread_self()) == 0);
    (void)atomic_fetch_add(&f->executions, 1);
    vireo_task_info_t info;
    vireo_task_payload_view_t view;
    assert(vireo_task_inspect(task, &info) == VIREO_OK);
    assert(info.metadata.request_instance_id == 1 || info.metadata.request_instance_id == 2);
    size_t const index = (size_t)(info.metadata.request_instance_id - 1);
    assert(vireo_task_borrow_payload(task, &view) == VIREO_OK);
    assert(view.size == (index == 0 ? 8 : 64));
    assert(vireo_auth_password_validate(view.data, view.size) == VIREO_OK);
    int const code = pthread_barrier_wait(&f->entered);
    assert(code == 0 || code == PTHREAD_BARRIER_SERIAL_THREAD);
    errno = EDOM;
    assert(vireo_auth_password_hash_create(f->gate, view.data, view.size, f->encoded[index],
        sizeof(f->encoded[index]), &f->lengths[index]) == VIREO_OK && errno == EDOM);
    vireo_password_policy_t const policy = VIREO_PASSWORD_POLICY_DEFAULT;
    vireo_password_info_t password_info;
    assert(vireo_password_hash_inspect(&policy, f->encoded[index], f->lengths[index], &password_info) == VIREO_OK);
    assert(password_info.memory_kib == 65536 && password_info.iterations == 3 && password_info.parallelism == 1);
    bool matches = false;
    assert(vireo_auth_password_hash_verify(f->gate, view.data, view.size, f->encoded[index],
        f->lengths[index], &matches) == VIREO_OK && matches && errno == EDOM);
    unsigned char changed[64];
    memcpy(changed, view.data, view.size);
    changed[0] = view.data[0] == 'a' ? 'A' : 'a';
    assert(vireo_auth_password_hash_verify(f->gate, changed, view.size, f->encoded[index],
        f->lengths[index], &matches) == VIREO_OK && !matches && errno == EDOM);
    assert(view.data[0] != changed[0]);
    OPENSSL_cleanse(changed, sizeof(changed));
    f->done[index] = true;
    return VIREO_OK;
}

int main(void)
{
    worker_fixture_t f = {.manager = pthread_self()};
    assert(pthread_barrier_init(&f.entered, NULL, 2) == 0);
    vireo_auth_password_gate_options_t const gate_options = VIREO_AUTH_PASSWORD_GATE_OPTIONS_DEFAULT;
    assert(vireo_auth_password_gate_create(&gate_options, &f.gate) == VIREO_OK);
    vireo_task_queue_t *queue = NULL;
    vireo_thread_pool_t *pool = NULL;
    vireo_task_queue_options_t const queue_options = {2, 65536};
    vireo_thread_pool_options_t const pool_options = {2, 65536};
    assert(vireo_task_queue_create(&queue_options, &queue) == VIREO_OK);
    assert(vireo_task_queue_prepare_wait(queue) == VIREO_OK);
    assert(vireo_thread_pool_create(&pool_options, &pool) == VIREO_OK);
    vireo_thread_pool_configuration_t const configuration = {queue, execute, &f};
    assert(vireo_thread_pool_configure(pool, &configuration, NULL) == VIREO_OK);
    vireo_thread_pool_report_t report;
    assert(vireo_thread_pool_start(pool, &report) == VIREO_OK && report.created_count == 2);
    assert(vireo_thread_pool_enable_execution(pool, &report) == VIREO_OK);
    vireo_auth_login_admission_options_t options = VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT;
    options.account.burst_tokens = 2;
    vireo_auth_login_admission_t *admission = NULL;
    assert(vireo_auth_login_admission_create(&options, 0, &admission) == VIREO_OK);
    vireo_auth_login_peer_t const peer = {4, {192,0,2,1}};
    unsigned char const device[16] = {0};
    vireo_rate_limit_decision_t decision;
    for (size_t i = 0; i < 5; ++i) {
        assert(vireo_auth_login_admission_check(admission, 0, &peer,
            i % 2 == 0 ? "Alice" : "ALICE", 5, device, &decision) == VIREO_OK);
        if (i >= 2) {
            assert(decision.outcome == VIREO_RATE_LIMIT_THROTTLED &&
                decision.retry_after_ns == UINT64_C(30000000000));
            continue;
        }
        assert(decision.outcome == VIREO_RATE_LIMIT_ADMITTED);
        vireo_task_metadata_t metadata;
        vireo_task_route_t route;
        assert(vireo_task_route_make(1, 1, 1, (uint32_t)(i + 1), &route) == VIREO_OK);
        assert(vireo_task_metadata_make(route, i + 1, 1, UINT64_MAX, &metadata) == VIREO_OK);
        unsigned char bytes[64];
        /* 最小长度覆盖引号/反斜杠；最大长度覆盖全部大小写/数字及多种符号。 */
        if (i == 0) { memcpy(bytes, "a\"'\\[]~!", 8); }
        else {
            char const pattern[] = "aZ09!@#$%^&*()_+-={}[]:;\"'\\|<>,.?/~`";
            for (size_t j = 0; j < sizeof(bytes); ++j) { bytes[j] = (unsigned char)pattern[j % (sizeof(pattern) - 1)]; }
        }
        vireo_task_t *task = NULL;
        assert(vireo_task_create_copy(metadata, bytes, i == 0 ? 8 : 64, 4096, &task) == VIREO_OK);
        OPENSSL_cleanse(bytes, sizeof(bytes));
        submit_task(pool, &task);
    }
    vireo_thread_pool_shutdown_report_t shutdown;
    assert(vireo_thread_pool_shutdown_and_join(pool, VIREO_TASK_QUEUE_DRAIN, &shutdown) == VIREO_OK);
    assert(shutdown.pool_report.joined_count == 2 && f.done[0] && f.done[1]);
    assert(atomic_load(&f.executions) == 2);
    /* 即使前两次工作已处理完，尝试额度也不自动退回；无Session数量含义。 */
    assert(vireo_auth_login_admission_check(admission, 0, &peer, "alice", 5, device, &decision) == VIREO_OK &&
        decision.outcome == VIREO_RATE_LIMIT_THROTTLED);
    assert(vireo_auth_login_admission_destroy(&admission) == VIREO_OK && admission == NULL);
    assert(strcmp(f.encoded[0], f.encoded[1]) != 0);
    assert(vireo_thread_pool_destroy(&pool) == VIREO_OK && pool == NULL);
    assert(vireo_task_queue_destroy(&queue) == VIREO_OK && queue == NULL);
    assert(pthread_barrier_destroy(&f.entered) == 0);
    assert(vireo_auth_password_gate_close(f.gate) == VIREO_OK);
    bool matches = false;
    assert(vireo_auth_password_hash_verify(f.gate, "abcdefgh", 8, f.encoded[0],
        f.lengths[0], &matches) == VIREO_RESULT_CANCELLED && !matches);
    assert(vireo_auth_password_gate_destroy(&f.gate) == VIREO_OK && f.gate == NULL);
    OPENSSL_cleanse(f.encoded, sizeof(f.encoded));
    puts("PASS real admission -> public pool -> shared KDF gate: 2 accepted workers/3 rejected attempts; no execution/refund on refusal or completion; native Argon2 and drain/join; no network/DB claims");
    return 0;
}
