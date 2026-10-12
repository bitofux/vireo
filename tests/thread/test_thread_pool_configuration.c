/*
 * PROJECT : VIREO
 * FILE    : test_thread_pool_configuration.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 真实队列装配、借用保持与局部观测错误透传
 */

#include "thread/thread_pool_internal.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

_Static_assert(VIREO_THREAD_POOL_CONFIGURE_STAGE_NONE == 0, "NONE stage");
_Static_assert(VIREO_THREAD_POOL_CONFIGURE_STAGE_CHECK_QUEUE == 1, "queue stage");

/**
 * @brief
 *     本测试的执行次数，装配全过程必须为零。
 */
typedef struct execution_trace {
    size_t calls; /**< 仅若测试执行入口被错误调用才增加，不是运行期指标。 */
} execution_trace_t;

/**
 * @brief
 *     单线程测试持有的独立 pool/queue owner 和上下文。
 */
typedef struct pool_fixture {
    vireo_thread_pool_t *pool; /**< 唯一 pool owner，先销毁以结束借用。 */
    vireo_task_queue_t *queue; /**< 独立唯一 queue owner，不由 pool 释放。 */
    execution_trace_t execution; /**< 借用目标，活到 pool 销毁之后。 */
} pool_fixture_t;

/**
 * @brief
 *     仅本核心 seam 的局部观测脚本，不访问依赖私有状态。
 */
typedef struct inspection_trace {
    vireo_result_t result; /**< 注入的原返回值；仅 OK 才发布脚本快照。 */
    size_t calls; /**< 本次观测次数，基本/重复路径须为零，检查路径须为一。 */
    vireo_task_queue_t const *expected_queue; /**< 短借的真实队列地址，不拥有它。 */
    vireo_task_queue_info_t info; /**< 脚本成功时的公开逻辑快照，不代表真实损坏资源。 */
    bool mismatch; /**< 适配输入不符时记录的测试诊断，初 false。 */
} inspection_trace_t;

/**
 * @brief
 *     可合法读取 task 的未来执行入口；本项产品不得调用。
 *
 * @param[in,out] context
 *     本 fixture 的独占计数，可 NULL。
 * @param[in] task
 *     如果被调用，必须是合法只读借用，不接管拥有权。
 *
 * @return
 *     公开 task_inspect 结果，不模拟 completion 或 worker。
 */
static vireo_result_t execute_task(void *context, vireo_task_t const *task) {
    execution_trace_t *trace = context;
    if (trace != NULL) { ++trace->calls; }
    vireo_task_info_t info;
    return vireo_task_inspect(task, &info);
}

/**
 * @brief
 *     局部观测注入仅测试 pool 对返回值的处理，不修改真实 queue。
 *
 * @param[in,out] context
 *     必需独占 trace，借至本次配置返回。
 * @param[in] queue
 *     与 expected_queue 相同的真实存活短借地址。
 * @param[out] out_info
 *     必需独立输出；只有脚本 result 为 OK 才发布。
 *
 * @return
 *     trace 的原返回值；故意扰动 errno 验证外层恢复。
 */
static vireo_result_t scripted_inspect(void *context, vireo_task_queue_t const *queue,
                                     vireo_task_queue_info_t *out_info) {
    inspection_trace_t *trace = context;
    ++trace->calls;
    if (queue != trace->expected_queue || out_info == NULL) { trace->mismatch = true; }
    if (trace->result == VIREO_OK && out_info != NULL) { *out_info = trace->info; }
    errno = EIO;
    return trace->result;
}

/**
 * @brief
 *     建立独立空资源；任一步创建失败后配对清理已拥有部分。
 *
 * @param[out] fixture
 *     必需新独占存储，初始化全部 owner 和计数。
 * @param[in] prepare
 *     是否显式准备队列等待，不启动任何线程。
 *
 * @return
 *     实际依赖错误；正常为 OK。
 */
static vireo_result_t make_fixture(pool_fixture_t *fixture, bool prepare) {
    *fixture = (pool_fixture_t){0};
    vireo_thread_pool_options_t const pool_options = {3, 4096};
    vireo_task_queue_options_t const queue_options = {3, 4096};
    vireo_result_t result = vireo_thread_pool_create(&pool_options, &fixture->pool);
    if (result != VIREO_OK) { return result; }
    result = vireo_task_queue_create(&queue_options, &fixture->queue);
    if (result == VIREO_OK && prepare) { result = vireo_task_queue_prepare_wait(fixture->queue); }
    if (result != VIREO_OK) {
        vireo_result_t const queue_cleanup = vireo_task_queue_destroy(&fixture->queue);
        vireo_result_t const pool_cleanup = vireo_thread_pool_destroy(&fixture->pool);
        if (queue_cleanup != VIREO_OK) { return queue_cleanup; }
        if (pool_cleanup != VIREO_OK) { return pool_cleanup; }
    }
    return result;
}

/**
 * @brief
 *     无访问/线程时先结束 pool 借用，再由 caller 释放独立空 queue。
 *
 * @param[in,out] fixture
 *     独占 fixture，queue 必须为空；失败资源 owner 留给调用者。
 *
 * @return
 *     实际清理结果，无自动关闭、排空或重试。
 */
static vireo_result_t destroy_fixture(pool_fixture_t *fixture) {
    vireo_result_t result = vireo_thread_pool_destroy(&fixture->pool);
    if (result != VIREO_OK) { return result; }
    return vireo_task_queue_destroy(&fixture->queue);
}

/**
 * @brief
 *     仅本核心白盒核未发布关联，线程句柄从不读取。
 */
static bool unconfigured(vireo_thread_pool_t const *pool) {
    if (pool->configured || pool->configuration.queue != NULL ||
        pool->configuration.execute != NULL || pool->configuration.context != NULL) {
        return false;
    }
    for (size_t i = 0; i < pool->worker_count; ++i) {
        if (pool->workers[i].thread_created) { return false; }
    }
    return true;
}

/**
 * @brief
 *     用公开 route/metadata/create_copy 构造无取消的独立真实 task。
 *
 * @param[out] out_task
 *     必需独占空 owner，失败保持，成功由调用者销毁或转交。
 *
 * @return
 *     公开依赖原结果；不认证实际客户或执行任务。
 */
static vireo_result_t make_task(vireo_task_t **out_task) {
    vireo_task_route_t route;
    vireo_result_t result = vireo_task_route_make(1, 0, 1, 1, &route);
    if (result != VIREO_OK) { return result; }
    vireo_task_metadata_t metadata;
    result = vireo_task_metadata_make(route, 1, 1, 0, &metadata);
    if (result != VIREO_OK) { return result; }
    unsigned char const payload[] = {7, 0, 42};
    return vireo_task_create_copy(metadata, payload, sizeof(payload), 4096, out_task);
}

/**
 * @brief
 *     真队列成功装配、配置副本和四字段快照，销毁不消费 queue。
 */
static int configuration_lifecycle(void) {
    pool_fixture_t f;
    errno = EDOM;
    CHECK(make_fixture(&f, true) == VIREO_OK && errno == EDOM);
    CHECK(unconfigured(f.pool));
    vireo_thread_pool_info_t before;
    CHECK(vireo_thread_pool_inspect(f.pool, &before) == VIREO_OK && !before.configured);
    vireo_thread_pool_configuration_t c = {f.queue, execute_task, &f.execution};
    vireo_thread_pool_configure_stage_t stage = VIREO_THREAD_POOL_CONFIGURE_STAGE_CHECK_QUEUE;
    CHECK(vireo_thread_pool_configure(f.pool, &c, &stage) == VIREO_OK && errno == EDOM);
    CHECK(stage == VIREO_THREAD_POOL_CONFIGURE_STAGE_NONE && f.execution.calls == 0);
    c = (vireo_thread_pool_configuration_t){NULL, NULL, NULL};
    CHECK(f.pool->configuration.queue == f.queue);
    CHECK(f.pool->configuration.execute == execute_task);
    CHECK(f.pool->configuration.context == &f.execution);
    for (size_t i = 0; i < f.pool->worker_count; ++i) { CHECK(!f.pool->workers[i].thread_created); }
    vireo_thread_pool_info_t after;
    CHECK(vireo_thread_pool_inspect(f.pool, &after) == VIREO_OK && after.configured);
    CHECK(after.worker_count == before.worker_count && after.allocated_bytes == before.allocated_bytes);
    CHECK(after.max_memory_bytes == before.max_memory_bytes);
    CHECK(vireo_thread_pool_destroy(&f.pool) == VIREO_OK && f.pool == NULL && errno == EDOM);
    CHECK(after.configured && after.worker_count == 3 && f.execution.calls == 0);
    vireo_task_queue_info_t queue_info;
    CHECK(vireo_task_queue_inspect(f.queue, &queue_info) == VIREO_OK);
    CHECK(queue_info.state == VIREO_TASK_QUEUE_OPEN && queue_info.count == 0 && queue_info.wait_prepared);
    CHECK(destroy_fixture(&f) == VIREO_OK && f.queue == NULL && errno == EDOM);
    return 0;
}

/**
 * @brief
 *     context/stage 可空不会妨碍装配，handler 地址仍保存。
 */
static int optional_arguments(void) {
    pool_fixture_t f;
    CHECK(make_fixture(&f, true) == VIREO_OK);
    vireo_thread_pool_configuration_t const c = {f.queue, execute_task, NULL};
    errno = ENOTTY;
    CHECK(vireo_thread_pool_configure(f.pool, &c, NULL) == VIREO_OK && errno == ENOTTY);
    CHECK(f.pool->configured && f.pool->configuration.context == NULL);
    CHECK(f.pool->configuration.execute == execute_task && f.execution.calls == 0);
    CHECK(destroy_fixture(&f) == VIREO_OK && errno == ENOTTY);
    return 0;
}

/**
 * @brief
 *     基本地址/函数无效优先，stage 覆盖且未发布任何借用。
 */
static int basic_guards(void) {
    pool_fixture_t f;
    CHECK(make_fixture(&f, true) == VIREO_OK);
    vireo_thread_pool_configuration_t c = {f.queue, execute_task, &f.execution};
    vireo_thread_pool_configure_stage_t stage = VIREO_THREAD_POOL_CONFIGURE_STAGE_CHECK_QUEUE;
    errno = EILSEQ;
    CHECK(vireo_thread_pool_configure(NULL, &c, &stage) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(stage == VIREO_THREAD_POOL_CONFIGURE_STAGE_NONE);
    stage = VIREO_THREAD_POOL_CONFIGURE_STAGE_CHECK_QUEUE;
    CHECK(vireo_thread_pool_configure(f.pool, NULL, &stage) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(stage == VIREO_THREAD_POOL_CONFIGURE_STAGE_NONE);
    c.queue = NULL;
    CHECK(vireo_thread_pool_configure(f.pool, &c, &stage) == VIREO_RESULT_INVALID_ARGUMENT);
    c.queue = f.queue; c.execute = NULL;
    CHECK(vireo_thread_pool_configure(f.pool, &c, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(unconfigured(f.pool) && f.execution.calls == 0 && errno == EILSEQ);
    CHECK(destroy_fixture(&f) == VIREO_OK && errno == EILSEQ);
    return 0;
}

/**
 * @brief
 *     未准备失败不自动 prepare，caller 准备后显式重试可成功。
 */
static int unprepared_queue(void) {
    pool_fixture_t f;
    CHECK(make_fixture(&f, false) == VIREO_OK);
    vireo_thread_pool_configuration_t const c = {f.queue, execute_task, &f.execution};
    vireo_thread_pool_configure_stage_t stage;
    errno = E2BIG;
    CHECK(vireo_thread_pool_configure(f.pool, &c, &stage) == VIREO_RESULT_NOT_FOUND);
    CHECK(stage == VIREO_THREAD_POOL_CONFIGURE_STAGE_CHECK_QUEUE && unconfigured(f.pool));
    vireo_task_queue_info_t info;
    CHECK(vireo_task_queue_inspect(f.queue, &info) == VIREO_OK && !info.wait_prepared);
    CHECK(vireo_task_queue_prepare_wait(f.queue) == VIREO_OK);
    CHECK(vireo_thread_pool_configure(f.pool, &c, &stage) == VIREO_OK && errno == E2BIG);
    CHECK(stage == VIREO_THREAD_POOL_CONFIGURE_STAGE_NONE && f.execution.calls == 0);
    CHECK(destroy_fixture(&f) == VIREO_OK && errno == E2BIG);
    return 0;
}

/**
 * @brief
 *     两种永久关闭均拒绝，关闭检查优先于未准备，不改变关闭模式。
 */
static int closed_queue(void) {
    vireo_task_queue_state_t const modes[] = {VIREO_TASK_QUEUE_DRAIN, VIREO_TASK_QUEUE_CANCEL_PENDING};
    for (size_t i = 0; i < 2; ++i) {
        for (size_t j = 0; j < 2; ++j) {
            pool_fixture_t f;
            CHECK(make_fixture(&f, j != 0) == VIREO_OK);
            vireo_task_queue_close_report_t close_report;
            CHECK(vireo_task_queue_close(f.queue, modes[i], &close_report) == VIREO_OK);
            vireo_thread_pool_configuration_t const c = {f.queue, execute_task, &f.execution};
            vireo_thread_pool_configure_stage_t stage;
            errno = EDOM;
            CHECK(vireo_thread_pool_configure(f.pool, &c, &stage) == VIREO_RESULT_CANCELLED);
            CHECK(stage == VIREO_THREAD_POOL_CONFIGURE_STAGE_CHECK_QUEUE && unconfigured(f.pool));
            vireo_task_queue_info_t info;
            CHECK(vireo_task_queue_inspect(f.queue, &info) == VIREO_OK);
            CHECK(info.state == modes[i] && info.count == 0 && info.wait_prepared == (j != 0));
            CHECK(f.execution.calls == 0 && errno == EDOM);
            CHECK(destroy_fixture(&f) == VIREO_OK && errno == EDOM);
        }
    }
    return 0;
}

/**
 * @brief
 *     非空失败不丢真实 task，未准备优先非空，caller 领取后可显式装配。
 */
static int nonempty_queue(void) {
    for (size_t i = 0; i < 2; ++i) {
        pool_fixture_t f;
        CHECK(make_fixture(&f, i != 0) == VIREO_OK);
        vireo_task_t *task = NULL;
        CHECK(make_task(&task) == VIREO_OK);
        vireo_task_t const *identity = task;
        vireo_task_queue_transfer_report_t transfer;
        CHECK(vireo_task_queue_try_push(f.queue, &task, &transfer) == VIREO_OK && task == NULL);
        vireo_thread_pool_configuration_t const c = {f.queue, execute_task, &f.execution};
        vireo_thread_pool_configure_stage_t stage;
        errno = EILSEQ;
        CHECK(vireo_thread_pool_configure(f.pool, &c, &stage) ==
              (i != 0 ? VIREO_RESULT_BUSY : VIREO_RESULT_NOT_FOUND));
        CHECK(stage == VIREO_THREAD_POOL_CONFIGURE_STAGE_CHECK_QUEUE && unconfigured(f.pool));
        vireo_task_queue_info_t info;
        CHECK(vireo_task_queue_inspect(f.queue, &info) == VIREO_OK && info.count == 1);
        CHECK(vireo_task_queue_try_pop(f.queue, &task, &transfer) == VIREO_OK && task == identity);
        vireo_task_payload_view_t view;
        CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK && view.size == 3);
        CHECK(view.data[0] == 7 && view.data[1] == 0 && view.data[2] == 42);
        CHECK(vireo_task_destroy(&task) == VIREO_OK && task == NULL);
        CHECK(vireo_task_queue_prepare_wait(f.queue) == VIREO_OK);
        CHECK(vireo_thread_pool_configure(f.pool, &c, &stage) == VIREO_OK);
        CHECK(f.execution.calls == 0 && errno == EILSEQ);
        CHECK(destroy_fixture(&f) == VIREO_OK && errno == EILSEQ);
    }
    return 0;
}

/**
 * @brief
 *     已装配重复不观察新 queue，基本错误仍优先，保存原关联。
 */
static int repeated_configuration(void) {
    pool_fixture_t f;
    CHECK(make_fixture(&f, true) == VIREO_OK);
    vireo_thread_pool_configuration_t c = {f.queue, execute_task, &f.execution};
    CHECK(vireo_thread_pool_configure(f.pool, &c, NULL) == VIREO_OK);
    vireo_task_queue_t *other = NULL;
    vireo_task_queue_options_t const opts = {1, 4096};
    CHECK(vireo_task_queue_create(&opts, &other) == VIREO_OK);
    c.queue = other; c.context = NULL;
    inspection_trace_t trace = {.result = VIREO_RESULT_INTERNAL, .expected_queue = other};
    vireo_thread_pool_queue_inspector_t const inspector = {&trace, scripted_inspect};
    vireo_thread_pool_configure_stage_t stage = VIREO_THREAD_POOL_CONFIGURE_STAGE_CHECK_QUEUE;
    errno = ENOTTY;
    CHECK(vireo_thread_pool_configure(f.pool, &c, &stage) == VIREO_RESULT_BUSY);
    CHECK(stage == VIREO_THREAD_POOL_CONFIGURE_STAGE_NONE);
    CHECK(vireo_thread_pool_configure_with_inspector(f.pool, &c, &inspector, &stage) == VIREO_RESULT_BUSY);
    CHECK(trace.calls == 0 && stage == VIREO_THREAD_POOL_CONFIGURE_STAGE_NONE);
    c.execute = NULL;
    CHECK(vireo_thread_pool_configure(f.pool, &c, &stage) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(f.pool->configuration.queue == f.queue && f.pool->configuration.context == &f.execution);
    CHECK(f.pool->configuration.execute == execute_task && f.pool->configured);
    CHECK(f.execution.calls == 0 && errno == ENOTTY);
    CHECK(vireo_task_queue_destroy(&other) == VIREO_OK);
    CHECK(destroy_fixture(&f) == VIREO_OK && errno == ENOTTY);
    return 0;
}

/**
 * @brief
 *     own seam 所有依赖分类透传及非法操作表，不读失败快照、不发布。
 */
static int dependency_errors(void) {
    pool_fixture_t f;
    CHECK(make_fixture(&f, true) == VIREO_OK);
    vireo_thread_pool_configuration_t const c = {f.queue, execute_task, &f.execution};
    vireo_result_t const errors[] = {VIREO_RESULT_BUSY, VIREO_RESULT_INTERNAL,
        VIREO_RESULT_CANCELLED, VIREO_RESULT_INVALID_ARGUMENT, VIREO_RESULT_NOT_FOUND,
        VIREO_RESULT_IO};
    unsigned char previous[4096];
    size_t const pool_bytes = f.pool->allocated_bytes;
    CHECK(pool_bytes <= sizeof(previous));
    memcpy(previous, f.pool, pool_bytes);
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        inspection_trace_t trace = {.result = errors[i], .expected_queue = f.queue};
        vireo_thread_pool_queue_inspector_t const inspector = {&trace, scripted_inspect};
        vireo_thread_pool_configure_stage_t stage = VIREO_THREAD_POOL_CONFIGURE_STAGE_NONE;
        errno = E2BIG;
        CHECK(vireo_thread_pool_configure_with_inspector(f.pool, &c, &inspector, &stage) == errors[i]);
        CHECK(trace.calls == 1 && !trace.mismatch && unconfigured(f.pool));
        CHECK(memcmp(previous, f.pool, pool_bytes) == 0);
        CHECK(stage == VIREO_THREAD_POOL_CONFIGURE_STAGE_CHECK_QUEUE && errno == E2BIG);
    }
    vireo_thread_pool_queue_inspector_t bad = {NULL, NULL};
    vireo_thread_pool_configure_stage_t stage = VIREO_THREAD_POOL_CONFIGURE_STAGE_CHECK_QUEUE;
    CHECK(vireo_thread_pool_configure_with_inspector(f.pool, &c, NULL, &stage) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(stage == VIREO_THREAD_POOL_CONFIGURE_STAGE_NONE);
    CHECK(vireo_thread_pool_configure_with_inspector(f.pool, &c, &bad, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(unconfigured(f.pool) && f.execution.calls == 0);
    CHECK(vireo_thread_pool_configure(f.pool, &c, &stage) == VIREO_OK);
    CHECK(destroy_fixture(&f) == VIREO_OK && errno == E2BIG);
    return 0;
}

/**
 * @brief
 *     真关闭队列仍有 task 时，关闭优先非空；拒绝不会消费其拥有权。
 */
static int closed_nonempty_queue(void) {
    vireo_task_queue_state_t const modes[] = {VIREO_TASK_QUEUE_DRAIN, VIREO_TASK_QUEUE_CANCEL_PENDING};
    for (size_t i = 0; i < 2; ++i) {
        pool_fixture_t f;
        CHECK(make_fixture(&f, true) == VIREO_OK);
        vireo_task_t *task = NULL;
        CHECK(make_task(&task) == VIREO_OK);
        vireo_task_t const *identity = task;
        vireo_task_queue_transfer_report_t transfer;
        CHECK(vireo_task_queue_try_push(f.queue, &task, &transfer) == VIREO_OK && task == NULL);
        vireo_task_queue_close_report_t closed;
        CHECK(vireo_task_queue_close(f.queue, modes[i], &closed) == VIREO_OK);
        vireo_thread_pool_configuration_t const c = {f.queue, execute_task, &f.execution};
        vireo_thread_pool_configure_stage_t stage;
        errno = E2BIG;
        CHECK(vireo_thread_pool_configure(f.pool, &c, &stage) == VIREO_RESULT_CANCELLED);
        CHECK(stage == VIREO_THREAD_POOL_CONFIGURE_STAGE_CHECK_QUEUE && unconfigured(f.pool));
        vireo_task_queue_info_t info;
        CHECK(vireo_task_queue_inspect(f.queue, &info) == VIREO_OK && info.count == 1);
        CHECK(info.state == modes[i]);
        if (modes[i] == VIREO_TASK_QUEUE_DRAIN) {
            CHECK(vireo_task_queue_try_pop(f.queue, &task, &transfer) == VIREO_OK);
        } else {
            CHECK(vireo_task_queue_try_take_cancelled(f.queue, &task, &transfer) == VIREO_OK);
        }
        CHECK(task == identity && f.execution.calls == 0);
        CHECK(vireo_task_destroy(&task) == VIREO_OK && errno == E2BIG);
        CHECK(destroy_fixture(&f) == VIREO_OK && errno == E2BIG);
    }
    return 0;
}

/**
 * @brief
 *     装配后排队再销毁 pool，任务和 OPEN queue 仍可由 caller 完整领取清理。
 */
static int borrowed_resources_survive(void) {
    pool_fixture_t f;
    CHECK(make_fixture(&f, true) == VIREO_OK);
    vireo_thread_pool_configuration_t const c = {f.queue, execute_task, &f.execution};
    CHECK(vireo_thread_pool_configure(f.pool, &c, NULL) == VIREO_OK);
    vireo_task_t *task = NULL;
    CHECK(make_task(&task) == VIREO_OK);
    vireo_task_t const *identity = task;
    vireo_task_queue_transfer_report_t transfer;
    CHECK(vireo_task_queue_try_push(f.queue, &task, &transfer) == VIREO_OK && task == NULL);
    errno = EDOM;
    CHECK(vireo_thread_pool_destroy(&f.pool) == VIREO_OK && f.pool == NULL && f.execution.calls == 0);
    vireo_task_queue_info_t info;
    CHECK(vireo_task_queue_inspect(f.queue, &info) == VIREO_OK);
    CHECK(info.state == VIREO_TASK_QUEUE_OPEN && info.count == 1 && info.wait_prepared);
    CHECK(vireo_task_queue_try_pop(f.queue, &task, &transfer) == VIREO_OK && task == identity);
    CHECK(vireo_task_destroy(&task) == VIREO_OK && task == NULL && errno == EDOM);
    CHECK(destroy_fixture(&f) == VIREO_OK && errno == EDOM);
    return 0;
}

/**
 * @brief
 *     NULL 观测保持整个含 padding 的输出，成功快照只比较逻辑字段。
 */
static int info_output_preservation(void) {
    vireo_thread_pool_info_t info;
    memset(&info, 0xa5, sizeof(info));
    unsigned char previous[sizeof(info)];
    memcpy(previous, &info, sizeof(info));
    errno = EILSEQ;
    CHECK(vireo_thread_pool_inspect(NULL, &info) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(previous, &info, sizeof(info)) == 0 && errno == EILSEQ);
    pool_fixture_t f;
    CHECK(make_fixture(&f, true) == VIREO_OK);
    CHECK(vireo_thread_pool_inspect(f.pool, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_thread_pool_inspect(f.pool, &info) == VIREO_OK && !info.configured);
    CHECK(info.worker_count == 3 && info.allocated_bytes <= info.max_memory_bytes);
    CHECK(destroy_fixture(&f) == VIREO_OK && errno == EILSEQ);
    return 0;
}

int main(void) {
    CHECK(configuration_lifecycle() == 0);
    CHECK(optional_arguments() == 0);
    CHECK(basic_guards() == 0);
    CHECK(unprepared_queue() == 0);
    CHECK(closed_queue() == 0);
    CHECK(closed_nonempty_queue() == 0);
    CHECK(nonempty_queue() == 0);
    CHECK(repeated_configuration() == 0);
    CHECK(dependency_errors() == 0);
    CHECK(borrowed_resources_survive() == 0);
    CHECK(info_output_preservation() == 0);
    puts("test_thread_pool_configuration: 11 groups passed; no worker threads started or tasks executed");
    return 0;
}
