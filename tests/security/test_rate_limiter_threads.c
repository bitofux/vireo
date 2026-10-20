#define _POSIX_C_SOURCE 200809L
#include "rate_limiter_test.h"
#include <pthread.h>

typedef struct fixture {
    vireo_rate_limiter_t *limiter; /**< 管理端创建，join后才销毁。 */
    pthread_mutex_t mutex; /**< caller外部同步完整check，不是组件内部锁。 */
    pthread_barrier_t entered; /**< 两个真实线程先汇合，不使用sleep。 */
    size_t admitted; /**< 由同一外部mutex保护。 */
    size_t throttled; /**< 由同一外部mutex保护。 */
} fixture_t;

static void *execute(void *context) {
    fixture_t *fixture = context;
    int const joined = pthread_barrier_wait(&fixture->entered);
    CHECK(joined == 0 || joined == PTHREAD_BARRIER_SERIAL_THREAD);
    vireo_rate_limit_request_t const request = request_for(1, 0, 1);
    for (size_t i = 0; i < 100; ++i) {
        CHECK(pthread_mutex_lock(&fixture->mutex) == 0);
        /* 同一合法时刻由caller提供；没有在线程间先采时再乱序使用。 */
        vireo_rate_limit_decision_t decision;
        errno = EDOM;
        CHECK(vireo_rate_limiter_check(fixture->limiter, 100, &request, 1, &decision) == VIREO_OK);
        CHECK(errno == EDOM && decision.tracked_keys == 1);
        if (decision.outcome == VIREO_RATE_LIMIT_ADMITTED) {
            CHECK(decision.retry_after_ns == 0);
            ++fixture->admitted;
        } else {
            CHECK(decision.outcome == VIREO_RATE_LIMIT_THROTTLED && decision.retry_after_ns == 10);
            ++fixture->throttled;
        }
        CHECK(pthread_mutex_unlock(&fixture->mutex) == 0);
    }
    return NULL;
}

int main(void) {
    vireo_rate_limit_policy_t const policy = {1, 100, 10};
    fixture_t fixture = {.limiter = make_limiter(1, &policy, 1, 100)};
    CHECK(pthread_mutex_init(&fixture.mutex, NULL) == 0);
    CHECK(pthread_barrier_init(&fixture.entered, NULL, 2) == 0);
    pthread_t threads[2];
    CHECK(pthread_create(&threads[0], NULL, execute, &fixture) == 0);
    CHECK(pthread_create(&threads[1], NULL, execute, &fixture) == 0);
    CHECK(pthread_join(threads[0], NULL) == 0);
    CHECK(pthread_join(threads[1], NULL) == 0);
    CHECK(fixture.admitted == 100 && fixture.throttled == 100);
    vireo_rate_limiter_info_t info;
    CHECK(vireo_rate_limiter_inspect(fixture.limiter, &info) == VIREO_OK && info.last_now == 100);
    CHECK(vireo_rate_limiter_destroy(&fixture.limiter) == VIREO_OK && fixture.limiter == NULL);
    CHECK(pthread_mutex_destroy(&fixture.mutex) == 0);
    CHECK(pthread_barrier_destroy(&fixture.entered) == 0);
    puts("rate limiter threads: caller mutex, real two-thread barrier, 200 checks / exact 100 admissions, join before destruction passed");
    return 0;
}
