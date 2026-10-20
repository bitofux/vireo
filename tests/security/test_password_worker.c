#define _POSIX_C_SOURCE 200809L
#include "password_test.h"
#include <vireo/thread/thread_pool.h>
#include <pthread.h>

typedef struct worker_fixture {
    pthread_t manager; /**< 启动前设置，worker实际运行时比较身份。 */
    pthread_barrier_t entered; /**< 两个真实worker同时进入，避免一个worker串行完成两项。 */
    char encoded[2][128]; /**< 按任务实例分槽写，join后由管理端读取。 */
    size_t lengths[2]; /**< 各槽成功结果长度，独立写入。 */
    bool done[2]; /**< 对应任务调用完成；join建立跨线程可见性。 */
} worker_fixture_t;

static vireo_result_t execute(void *context, vireo_task_t const *task) {
    worker_fixture_t *fixture = context;
    CHECK(pthread_equal(fixture->manager, pthread_self()) == 0);
    vireo_task_info_t info;
    vireo_task_payload_view_t view;
    CHECK(vireo_task_inspect(task, &info) == VIREO_OK);
    CHECK(info.metadata.request_instance_id == 1 || info.metadata.request_instance_id == 2);
    size_t const index = (size_t)(info.metadata.request_instance_id - 1);
    CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK && view.size == 3);
    CHECK(view.data[0] == 'a' && view.data[1] == 0 && view.data[2] == (index == 0 ? 'b' : 'c'));
    int const barrier_result = pthread_barrier_wait(&fixture->entered);
    CHECK(barrier_result == 0 || barrier_result == PTHREAD_BARRIER_SERIAL_THREAD);
    vireo_password_policy_t const policy = VIREO_PASSWORD_POLICY_DEFAULT;
    bool matches = false;
    errno = EDOM;
    CHECK(vireo_password_hash_verify(&policy, view.data, view.size, KNOWN_PHC,
        sizeof(KNOWN_PHC) - 1, &matches) == VIREO_OK && matches == (index == 0) && errno == EDOM);
    CHECK(vireo_password_hash_create(&policy, view.data, view.size, fixture->encoded[index],
        sizeof(fixture->encoded[index]), &fixture->lengths[index]) == VIREO_OK && errno == EDOM);
    CHECK(vireo_password_hash_verify(&policy, view.data, view.size, fixture->encoded[index],
        fixture->lengths[index], &matches) == VIREO_OK && matches && errno == EDOM);
    CHECK(view.data[1] == 0); /* 计算只擦除内部副本，任务原字节仍有效。 */
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
        unsigned char bytes[] = {'a', 0, (unsigned char)(i == 0 ? 'b' : 'c')};
        vireo_task_t *task = NULL;
        CHECK(vireo_task_create_copy(metadata, bytes, sizeof(bytes), 4096, &task) == VIREO_OK);
        memset(bytes, 0, sizeof(bytes));
        vireo_thread_pool_submit_report_t submit;
        CHECK(vireo_thread_pool_try_submit(pool, &task, &submit) == VIREO_OK && task == NULL);
    }
    vireo_thread_pool_shutdown_report_t shutdown;
    CHECK(vireo_thread_pool_shutdown_and_join(pool, VIREO_TASK_QUEUE_DRAIN, &shutdown) == VIREO_OK);
    CHECK(shutdown.pool_report.joined_count == 2 && fixture.done[0] && fixture.done[1]);
    CHECK(strcmp(fixture.encoded[0], fixture.encoded[1]) != 0);
    CHECK(vireo_thread_pool_destroy(&pool) == VIREO_OK && pool == NULL);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && queue == NULL);
    CHECK(pthread_barrier_destroy(&fixture.entered) == 0);
    puts("password worker: two real workers, copied NUL payloads, independent KDF results, drain/join passed");
    return 0;
}
