#define _POSIX_C_SOURCE 200809L
#include "session_token_test.h"
#include <vireo/thread/thread_pool.h>
#include <pthread.h>
#include <sched.h>

typedef struct worker_fixture {
    pthread_t manager; /**< 启动前设置，验证执行者是worker。 */
    pthread_barrier_t entered; /**< 两个任务同步到达，确保两个真实worker。 */
    vireo_session_token_digest_t digests[2]; /**< 每个worker只写独立槽，join后读取。 */
    bool done[2]; /**< 独立完成位，join建立可见性。 */
} worker_fixture_t;

static vireo_result_t execute(void *context, vireo_task_t const *task) {
    worker_fixture_t *fixture = context;
    CHECK(pthread_equal(fixture->manager, pthread_self()) == 0);
    vireo_task_info_t info;
    vireo_task_payload_view_t view;
    CHECK(vireo_task_inspect(task, &info) == VIREO_OK);
    CHECK(info.metadata.request_instance_id == 1 || info.metadata.request_instance_id == 2);
    size_t const index = (size_t)(info.metadata.request_instance_id - 1);
    CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK && view.size == 32);
    int const barrier_result = pthread_barrier_wait(&fixture->entered);
    CHECK(barrier_result == 0 || barrier_result == PTHREAD_BARRIER_SERIAL_THREAD);
    vireo_session_token_t token;
    memcpy(token.bytes, view.data, sizeof(token.bytes));
    vireo_session_token_digest_t digest;
    unsigned char const range_digest[32] = RANGE_DIGEST_BYTES;
    unsigned char const zero_digest[32] = ZERO_DIGEST_BYTES;
    errno = EDOM;
    CHECK(vireo_session_token_digest(&token, &digest) == VIREO_OK && errno == EDOM);
    CHECK(memcmp(digest.bytes, index == 0 ? range_digest : zero_digest, sizeof(digest.bytes)) == 0);
    CHECK(vireo_session_token_clear(&token) == VIREO_OK && errno == EDOM);
    CHECK(vireo_session_token_generate(&token, &fixture->digests[index]) == VIREO_OK && errno == EDOM);
    CHECK(vireo_session_token_digest(&token, &digest) == VIREO_OK && errno == EDOM);
    bool matches = false;
    CHECK(vireo_session_token_digest_equal(&digest, &fixture->digests[index], &matches) == VIREO_OK);
    CHECK(matches && errno == EDOM);
    CHECK(vireo_session_token_clear(&token) == VIREO_OK && errno == EDOM);
    unsigned char const zero[32] = {0};
    CHECK(memcmp(token.bytes, zero, sizeof(zero)) == 0);
    CHECK(vireo_session_token_clear(&token) == VIREO_OK && errno == EDOM);
    /* task中的合成值仍在：局部clear不冒充清理task/completion。 */
    for (size_t i = 0; i < view.size; ++i) {
        CHECK(view.data[i] == (index == 0 ? (unsigned char)i : 0));
    }
    fixture->done[index] = true;
    return VIREO_OK;
}

int main(void) {
    worker_fixture_t fixture = {.manager = pthread_self()};
    CHECK(pthread_barrier_init(&fixture.entered, NULL, 2) == 0);
    vireo_task_queue_t *queue = NULL;
    vireo_thread_pool_t *pool = NULL;
    vireo_task_queue_options_t const queue_options = {2, 65536};
    vireo_thread_pool_options_t const pool_options = {2, 65536};
    CHECK(vireo_task_queue_create(&queue_options, &queue) == VIREO_OK);
    CHECK(vireo_task_queue_prepare_wait(queue) == VIREO_OK);
    CHECK(vireo_thread_pool_create(&pool_options, &pool) == VIREO_OK);
    vireo_thread_pool_configuration_t const configuration = {queue, execute, &fixture};
    CHECK(vireo_thread_pool_configure(pool, &configuration, NULL) == VIREO_OK);
    vireo_thread_pool_report_t report;
    CHECK(vireo_thread_pool_start(pool, &report) == VIREO_OK && report.created_count == 2);
    CHECK(vireo_thread_pool_enable_execution(pool, &report) == VIREO_OK);
    for (size_t i = 0; i < 2; ++i) {
        vireo_task_metadata_t metadata;
        vireo_task_route_t route;
        CHECK(vireo_task_route_make(1, 1, 1, (uint32_t)(i + 1), &route) == VIREO_OK);
        CHECK(vireo_task_metadata_make(route, i + 1, 1, UINT64_MAX, &metadata) == VIREO_OK);
        unsigned char bytes[32];
        for (size_t j = 0; j < sizeof(bytes); ++j) { bytes[j] = i == 0 ? (unsigned char)j : 0; }
        vireo_task_t *task = NULL;
        CHECK(vireo_task_create_copy(metadata, bytes, sizeof(bytes), 4096, &task) == VIREO_OK);
        memset(bytes, 0xff, sizeof(bytes));
        vireo_thread_pool_submit_report_t submit;
        /* try_submit可因锁竞争BUSY；只对未交接且仍拥有的同task有限让出CPU重试。 */
        vireo_result_t submitted = VIREO_RESULT_BUSY;
        for (size_t attempt = 0; attempt < 8192 && submitted == VIREO_RESULT_BUSY; ++attempt) {
            submitted = vireo_thread_pool_try_submit(pool, &task, &submit);
            if (submitted == VIREO_RESULT_BUSY) {
                CHECK(task != NULL && !submit.queue_report.transferred);
                (void)sched_yield();
            }
        }
        CHECK(submitted == VIREO_OK && task == NULL);
    }
    vireo_thread_pool_shutdown_report_t shutdown;
    CHECK(vireo_thread_pool_shutdown_and_join(pool, VIREO_TASK_QUEUE_DRAIN, &shutdown) == VIREO_OK);
    CHECK(shutdown.pool_report.joined_count == 2 && fixture.done[0] && fixture.done[1]);
    bool matches = true;
    CHECK(vireo_session_token_digest_equal(&fixture.digests[0], &fixture.digests[1], &matches) == VIREO_OK);
    CHECK(!matches);
    CHECK(vireo_thread_pool_destroy(&pool) == VIREO_OK && pool == NULL);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && queue == NULL);
    CHECK(pthread_barrier_destroy(&fixture.entered) == 0);
    puts("session token worker: two real workers, copied synthetic tasks, independent CSPRNG/digest results, local clear, drain/join passed");
    return 0;
}
