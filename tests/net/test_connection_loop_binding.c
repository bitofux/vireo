/*
- PROJECT : VIREO
- FILE    : test_connection_loop_binding.c
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 正式 public loop 与 connection 的就绪归属、严格关注和资源配对
- -- 自注销在途保护、逐对象登记故障及整体销毁后的安全释放
 */
#define _GNU_SOURCE
#include <vireo/net/connection.h>
#include "net/connection_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned failures;
#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ++failures; \
    } \
} while (0)
#define REQUIRE(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: required %s\n", __FILE__, __LINE__, #condition); \
        exit(2); \
    } \
} while (0)

/* fixture 内 owner 地址稳定；loop seam 的借用 context 覆盖对象整个生命周期。 */
typedef struct fixture {
    vireo_connection_t *connection;
    int peer, owned_fd;
    size_t adds, mods, dels;
    int fail_add, fail_mod, fail_del;
    vireo_event_loop_handle_t last_handle;
} fixture_t;

typedef enum action { OBSERVE, RECEIVE_ONE, SELF_DETACH, DEL_FAILURE, NEST, UPDATE } action_t;
typedef struct callback_context {
    fixture_t *fixture;
    vireo_event_loop_t **loop_owner;
    action_t action;
    size_t calls;
    uint32_t events;
    uint8_t received[16];
    size_t received_size;
    vireo_event_loop_t *nested_loop;
    fixture_t *outer;
} callback_context_t;

/**
 * @brief 按公开 inspect 取得完整按值状态，不延长任何借用
 *
 * @param[in] fixture
 *     存活测试上下文，connection owner 必须非空。
 *
 * @return 独立数值快照。
 *
 * @note 失败立即结束测试进程，不继续使用未初始化输出。
 */
static vireo_connection_info_t state(fixture_t const *fixture)
{
    vireo_connection_info_t info;
    REQUIRE(vireo_connection_inspect(fixture->connection, &info) == VIREO_OK);
    return info;
}

/* 合成的是本模块公共依赖失败，不访问或改写已封板 loop 的内部实现。 */
static vireo_result_t injected_error(vireo_event_loop_error_t *error,
                                     vireo_event_loop_stage_t stage, int cause)
{
    if (error != NULL) {
        *error = (vireo_event_loop_error_t){0};
        error->stage = stage;
        error->epoll_error.stage = stage == VIREO_EVENT_LOOP_STAGE_ADD ?
            VIREO_EPOLL_STAGE_ADD : stage == VIREO_EVENT_LOOP_STAGE_MOD ?
            VIREO_EPOLL_STAGE_MOD : VIREO_EPOLL_STAGE_DEL;
        error->epoll_error.system_errno = cause;
    }
    errno = cause;
    return VIREO_RESULT_IO;
}

/**
 * @brief 记录尚未发布的 ADD 状态，失败不改变公共 loop
 *
 * @param[in,out] context
 *     对象生命周期内存活的 fixture。
 * @param[in,out] loop
 *     正式公共 loop。
 * @param[in] registration
 *     按值输入，fd/context 必须对应本 fixture 对象。
 * @param[in,out] handle
 *     独立全零输出，真实成功后保存供测试观察。
 * @param[out] error
 *     可空独立公共诊断。
 *
 * @return 合成 IO 或真实公共 ADD 结果。
 *
 * @note 拒绝无注册副作用；故意改变 errno 以验证外层恢复。
 */
static vireo_result_t add_binding(void *context, vireo_event_loop_t *loop,
                                  vireo_event_loop_registration_t const *registration,
                                  vireo_event_loop_handle_t *handle,
                                  vireo_event_loop_error_t *error)
{
    fixture_t *f = context;
    CHECK(!state(f).loop_attached);
    CHECK(registration->fd == f->owned_fd && registration->context == f->connection);
    CHECK(handle->loop_id == 0 && handle->token == 0);
    ++f->adds;
    if (f->fail_add != 0) return injected_error(error, VIREO_EVENT_LOOP_STAGE_ADD, f->fail_add);
    vireo_result_t result = vireo_event_loop_add(loop, registration, handle, error);
    if (result == VIREO_OK) f->last_handle = *handle;
    errno = EDOM;
    return result;
}

/**
 * @brief 验证旧关注直到成功 MOD 之后才替换
 *
 * @param[in,out] context
 *     存活 fixture。
 * @param[in,out] loop
 *     正式公共 loop。
 * @param[in] handle
 *     当前真实身份。
 * @param[in] interests
 *     目标关注，与旧观察分开。
 * @param[out] error
 *     可空独立诊断。
 *
 * @return 注入 IO 或严格一次真实 MOD。
 *
 * @note 不保存注册资源借用副本；last_handle 仅测试身份比较。
 */
static vireo_result_t mod_binding(void *context, vireo_event_loop_t *loop,
                                  vireo_event_loop_handle_t handle, uint32_t interests,
                                  vireo_event_loop_error_t *error)
{
    fixture_t *f = context;
    vireo_event_loop_registration_t registration;
    REQUIRE(vireo_event_loop_registration_inspect(loop, handle, &registration) == VIREO_OK);
    CHECK(registration.interests == state(f).loop_interests);
    ++f->mods;
    if (f->fail_mod != 0) return injected_error(error, VIREO_EVENT_LOOP_STAGE_MOD, f->fail_mod);
    vireo_result_t result = vireo_event_loop_mod(loop, handle, interests, error);
    errno = EDOM;
    return result;
}

/**
 * @brief 保留失败 DEL 的真实注册与 context，成功才结束借用
 *
 * @param[in,out] context
 *     存活 fixture。
 * @param[in,out] loop
 *     正式公共 loop。
 * @param[in,out] handle
 *     当前有效身份，真实 DEL 成功才清零。
 * @param[out] error
 *     可空独立诊断。
 *
 * @return 注入 IO 或一次真实 DEL。
 *
 * @note 不 close/free 任何客户资源。
 */
static vireo_result_t del_binding(void *context, vireo_event_loop_t *loop,
                                  vireo_event_loop_handle_t *handle,
                                  vireo_event_loop_error_t *error)
{
    fixture_t *f = context;
    CHECK(state(f).loop_attached);
    CHECK(handle->token == f->last_handle.token && handle->loop_id == f->last_handle.loop_id);
    ++f->dels;
    if (f->fail_del != 0) return injected_error(error, VIREO_EVENT_LOOP_STAGE_DEL, f->fail_del);
    vireo_result_t result = vireo_event_loop_del(loop, handle, error);
    errno = EDOM;
    return result;
}

/**
 * @brief 用真实 socketpair 创建，转移成功后只从公共 connection 操作 socket
 *
 * @param[in,out] fixture
 *     独立存活 fixture 地址，初始化到全部清理结束都不搬移。
 * @param[in] seam
 *     true 使用逐对象绑定 seam，false 使用正式公共构造。
 *
 * @note peer 独立拥有；owned_fd 仅用于只读属性/关闭后失效观察。
 */
static void setup(fixture_t *fixture, bool seam)
{
    *fixture = (fixture_t){0};
    int pair[2];
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
    fixture->peer = pair[1];
    fixture->owned_fd = pair[0];
    vireo_connection_options_t options = {64, 64, 128};
    vireo_connection_loop_ops_t ops = {fixture, add_binding, mod_binding, del_binding};
    errno = E2BIG;
    REQUIRE((seam ? vireo_connection_create_with_loop_ops(&options, &pair[0], &ops,
                    &fixture->connection, NULL) :
             vireo_connection_create(&options, &pair[0], &fixture->connection, NULL)) == VIREO_OK);
    CHECK(pair[0] == -1 && errno == E2BIG);
    CHECK(!state(fixture).loop_attached && !state(fixture).callback_active);
    CHECK(state(fixture).loop_interests == 0);
}

/**
 * @brief 创建容量显式给出的真实 loop
 *
 * @param[in] registrations
 *     正客户登记容量，与原生批次容量分离。
 *
 * @return 唯一 loop owner，调用者负责在全部借用结束后销毁。
 *
 * @note 预算足够本次小容量；内部停止 pipe 与客户注册数分开。
 */
static vireo_event_loop_t *make_loop(size_t registrations)
{
    vireo_event_loop_t *loop = NULL;
    vireo_event_loop_options_t options = {8, 65536, registrations};
    REQUIRE(vireo_event_loop_create(&options, &loop, NULL) == VIREO_OK);
    return loop;
}

/**
 * @brief 销毁已解绑且没有在途回调的资源，验证 fd 实际消费
 *
 * @param[in,out] fixture
 *     存活独立上下文；全部借用读取已经结束，loop 记录已安全清除。
 *
 * @note 不自动访问可能失效的 loop；消费 connection/peer 两个 owner。
 */
static void cleanup(fixture_t *fixture)
{
    REQUIRE(!state(fixture).loop_attached && !state(fixture).callback_active);
    errno = E2BIG;
    REQUIRE(vireo_connection_destroy(&fixture->connection, NULL) == VIREO_OK);
    CHECK(fixture->connection == NULL && errno == E2BIG);
    CHECK(fcntl(fixture->owned_fd, F_GETFD) == -1 && errno == EBADF);
    if (fixture->peer >= 0) REQUIRE(close(fixture->peer) == 0);
    fixture->peer = -1;
}

static void check_clear(vireo_connection_loop_error_t const *error)
{
    CHECK(error->stage == VIREO_CONNECTION_LOOP_STAGE_NONE);
    CHECK(error->loop_error.stage == VIREO_EVENT_LOOP_STAGE_NONE);
    CHECK(error->loop_error.system_errno == 0);
    CHECK(error->loop_error.epoll_error.stage == VIREO_EPOLL_STAGE_NONE);
    CHECK(error->loop_error.epoll_error.system_errno == 0);
}

/* 回调故意改变 errno；loop 对调用者恢复其入口值。 */
static void callback(vireo_connection_t *connection, uint32_t events, void *context)
{
    callback_context_t *c = context;
    REQUIRE(c != NULL && c->fixture->connection == connection);
    CHECK(state(c->fixture).callback_active);
    ++c->calls;
    c->events |= events;
    if (c->outer != NULL) {
        CHECK(state(c->outer).callback_active);
        CHECK(vireo_connection_destroy(&c->outer->connection, NULL) == VIREO_RESULT_BUSY);
    }
    if (c->action == RECEIVE_ONE) {
        vireo_connection_receive_budget_t budget = {1, 1};
        vireo_connection_receive_info_t info;
        REQUIRE(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_OK);
        CHECK(info.received_bytes == 1 && info.recv_calls == 1);
        uint8_t const *data;
        size_t size;
        REQUIRE(vireo_connection_read_peek(connection, &data, &size) == VIREO_OK);
        REQUIRE(size == 1 && c->received_size < sizeof(c->received));
        c->received[c->received_size++] = data[0];
        REQUIRE(vireo_connection_read_consume(connection, 1) == VIREO_OK);
    }
    if (c->action == SELF_DETACH || c->action == DEL_FAILURE) {
        vireo_connection_loop_error_t error;
        memset(&error, 0xa5, sizeof(error));
        size_t calls = c->fixture->dels;
        vireo_result_t result = vireo_connection_detach(connection, &error);
        CHECK(c->fixture->dels == calls + 1);
        if (c->action == DEL_FAILURE) {
            CHECK(result == VIREO_RESULT_IO && state(c->fixture).loop_attached);
            CHECK(error.loop_error.epoll_error.system_errno == EINTR);
        } else {
            CHECK(result == VIREO_OK && !state(c->fixture).loop_attached);
            check_clear(&error);
            REQUIRE(vireo_connection_detach(connection, NULL) == VIREO_OK);
            CHECK(c->fixture->dels == calls + 1);
            CHECK(vireo_connection_set_interests(connection, 0, NULL) == VIREO_RESULT_NOT_FOUND);
        }
        CHECK(state(c->fixture).callback_active);
        vireo_connection_error_t socket_error;
        memset(&socket_error, 0xa5, sizeof(socket_error));
        CHECK(vireo_connection_destroy(&c->fixture->connection, &socket_error) ==
              VIREO_RESULT_BUSY);
        CHECK(socket_error.stage == VIREO_CONNECTION_STAGE_NONE && socket_error.system_errno == 0);
        CHECK(vireo_connection_attach(connection, *c->loop_owner, 0, callback, c, &error) ==
              VIREO_RESULT_BUSY);
        check_clear(&error);
        CHECK(vireo_connection_forget_destroyed_loop(connection, &error) == VIREO_RESULT_BUSY);
        check_clear(&error);
        vireo_event_loop_run_info_t stats;
        memset(&stats, 0xa5, sizeof(stats));
        vireo_event_loop_run_info_t before = stats;
        CHECK(vireo_event_loop_run_once(*c->loop_owner, 0, &stats, NULL) == VIREO_RESULT_BUSY);
        CHECK(memcmp(&stats, &before, sizeof(stats)) == 0);
        CHECK(vireo_event_loop_destroy(c->loop_owner, NULL) == VIREO_RESULT_BUSY);
        CHECK(*c->loop_owner != NULL);
    }
    if (c->action == UPDATE) {
        REQUIRE(vireo_connection_set_interests(connection, 0, NULL) == VIREO_OK);
        CHECK(state(c->fixture).loop_interests == 0 && state(c->fixture).callback_active);
    }
    if (c->action == NEST) {
        vireo_event_loop_run_info_t stats;
        REQUIRE(vireo_event_loop_run_once(c->nested_loop, 0, &stats, NULL) == VIREO_OK);
        CHECK(stats.dispatched_count == 1 && state(c->fixture).callback_active);
    }
    errno = ERANGE;
}

/* NULL 业务 context 合法；只记录已有就绪，不持有 connection 别名。 */
static size_t null_context_calls;
static void null_context_callback(vireo_connection_t *connection, uint32_t events, void *context)
{
    vireo_connection_info_t info;
    REQUIRE(vireo_connection_inspect(connection, &info) == VIREO_OK);
    CHECK(context == NULL && info.callback_active &&
          (events & (VIREO_EPOLL_EVENT_ERROR | VIREO_EPOLL_EVENT_HANGUP)) != 0);
    ++null_context_calls;
}

static vireo_event_loop_run_info_t run(vireo_event_loop_t *loop)
{
    vireo_event_loop_run_info_t info;
    errno = E2BIG;
    REQUIRE(vireo_event_loop_run_once(loop, 0, &info, NULL) == VIREO_OK);
    CHECK(errno == E2BIG);
    return info;
}

static void attach(fixture_t *fixture, vireo_event_loop_t *loop, uint32_t interests,
                    callback_context_t *context)
{
    vireo_connection_loop_error_t error;
    memset(&error, 0xa5, sizeof(error));
    errno = E2BIG;
    REQUIRE(vireo_connection_attach(fixture->connection, loop, interests, callback,
                                     context, &error) == VIREO_OK);
    CHECK(errno == E2BIG);
    check_clear(&error);
    CHECK(state(fixture).loop_attached && state(fixture).loop_interests == interests);
}

static void test_public_binding(void)
{
    fixture_t f;
    setup(&f, false);
    vireo_event_loop_t *loop = make_loop(2);
    callback_context_t c = {.fixture = &f, .loop_owner = &loop};
    int flags = fcntl(f.owned_fd, F_GETFL), fd_flags = fcntl(f.owned_fd, F_GETFD);
    attach(&f, loop, VIREO_EPOLL_INTEREST_READ, &c);
    CHECK(run(loop).dispatched_count == 0);
    REQUIRE(send(f.peer, "ABC", 3, MSG_NOSIGNAL) == 3);
    CHECK(run(loop).dispatched_count == 1 && c.calls == 1);
    CHECK(c.events == VIREO_EPOLL_EVENT_READ && !state(&f).callback_active);
    CHECK(state(&f).read_buffer.readable_size == 0); /* 包装回调不替业务 recv。 */
    CHECK(fcntl(f.owned_fd, F_GETFL) == flags && fcntl(f.owned_fd, F_GETFD) == fd_flags);
    CHECK(vireo_connection_destroy(&f.connection, NULL) == VIREO_RESULT_BUSY);
    REQUIRE(vireo_connection_detach(f.connection, NULL) == VIREO_OK);
    CHECK(run(loop).dispatched_count == 0 && c.calls == 1);
    cleanup(&f);
    REQUIRE(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
}

static void test_parameters(void)
{
    fixture_t f;
    setup(&f, true);
    vireo_event_loop_t *loop = make_loop(2);
    callback_context_t c = {.fixture = &f, .loop_owner = &loop};
    vireo_connection_loop_error_t e;
    errno = E2BIG;
    CHECK(vireo_connection_attach(NULL, loop, 0, callback, &c, &e) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    check_clear(&e);
    CHECK(vireo_connection_attach(f.connection, NULL, 0, callback, &c, &e) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    check_clear(&e);
    CHECK(vireo_connection_attach(f.connection, loop, 0, NULL, &c, &e) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_attach(f.connection, loop, UINT32_MAX, callback, &c, &e) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    check_clear(&e);
    CHECK(vireo_connection_set_interests(NULL, 0, &e) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_set_interests(f.connection, VIREO_EPOLL_EVENT_ERROR, &e) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_set_interests(f.connection, 0, &e) == VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_connection_detach(NULL, &e) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_forget_destroyed_loop(NULL, &e) == VIREO_RESULT_INVALID_ARGUMENT);
    check_clear(&e);
    REQUIRE(vireo_connection_detach(f.connection, &e) == VIREO_OK);
    REQUIRE(vireo_connection_forget_destroyed_loop(f.connection, &e) == VIREO_OK);
    check_clear(&e);
    CHECK(errno == E2BIG && f.adds == 0 && f.mods == 0 && f.dels == 0);
    cleanup(&f);
    REQUIRE(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
}

static void test_repeat_and_same_mod(void)
{
    fixture_t f;
    setup(&f, true);
    vireo_event_loop_t *loop = make_loop(1), *other = make_loop(1);
    callback_context_t c = {.fixture = &f, .loop_owner = &loop};
    attach(&f, loop, VIREO_EPOLL_INTEREST_WRITE, &c);
    CHECK(vireo_connection_attach(f.connection, other, 0, callback, &c, NULL) == VIREO_RESULT_BUSY);
    CHECK(f.adds == 1 && f.mods == 0);
    CHECK(vireo_connection_set_interests(f.connection, UINT32_MAX, NULL) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(state(&f).loop_interests == VIREO_EPOLL_INTEREST_WRITE && f.mods == 0);
    errno = E2BIG;
    REQUIRE(vireo_connection_set_interests(f.connection, VIREO_EPOLL_INTEREST_WRITE, NULL) ==
            VIREO_OK);
    CHECK(f.mods == 1 && errno == E2BIG);
    REQUIRE(vireo_connection_set_interests(f.connection, 0, NULL) == VIREO_OK);
    CHECK(f.mods == 2 && run(loop).dispatched_count == 0);
    REQUIRE(vireo_connection_set_interests(f.connection, VIREO_EPOLL_INTEREST_WRITE, NULL) ==
            VIREO_OK);
    CHECK(run(loop).dispatched_count == 1);
    REQUIRE(vireo_connection_detach(f.connection, NULL) == VIREO_OK);
    REQUIRE(vireo_connection_detach(f.connection, NULL) == VIREO_OK);
    CHECK(f.dels == 1);
    attach(&f, other, 0, &c);
    REQUIRE(vireo_connection_detach(f.connection, NULL) == VIREO_OK);
    cleanup(&f);
    REQUIRE(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    REQUIRE(vireo_event_loop_destroy(&other, NULL) == VIREO_OK);
}

static void test_zero_and_null_context(void)
{
    fixture_t f;
    setup(&f, false);
    vireo_event_loop_t *loop = make_loop(1);
    null_context_calls = 0;
    REQUIRE(vireo_connection_attach(f.connection, loop, 0, null_context_callback, NULL, NULL) ==
            VIREO_OK);
    REQUIRE(send(f.peer, "A", 1, MSG_NOSIGNAL) == 1);
    CHECK(run(loop).dispatched_count == 0);
    REQUIRE(close(f.peer) == 0);
    f.peer = -1;
    CHECK(run(loop).dispatched_count == 1 && null_context_calls == 1);
    REQUIRE(vireo_connection_detach(f.connection, NULL) == VIREO_OK);
    cleanup(&f);
    REQUIRE(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
}

static void test_callback_receive_budget(void)
{
    fixture_t f;
    setup(&f, false);
    vireo_event_loop_t *loop = make_loop(1);
    callback_context_t c = {.fixture = &f, .loop_owner = &loop, .action = RECEIVE_ONE};
    attach(&f, loop, VIREO_EPOLL_INTEREST_READ, &c);
    REQUIRE(send(f.peer, "ABC", 3, MSG_NOSIGNAL) == 3);
    for (size_t i = 0; i < 3; ++i) CHECK(run(loop).dispatched_count == 1);
    CHECK(c.calls == 3 && c.received_size == 3 && memcmp(c.received, "ABC", 3) == 0);
    CHECK(run(loop).dispatched_count == 0);
    REQUIRE(vireo_connection_detach(f.connection, NULL) == VIREO_OK);
    cleanup(&f);
    REQUIRE(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
}

/* 当前回调里的成功 MOD 立即提交，但本次包装回调必须保持在途到返回。 */
static void test_callback_update(void)
{
    fixture_t f;
    setup(&f, true);
    vireo_event_loop_t *loop = make_loop(1);
    callback_context_t c = {.fixture = &f, .action = UPDATE};
    attach(&f, loop, VIREO_EPOLL_INTEREST_WRITE, &c);
    CHECK(run(loop).dispatched_count == 1 && f.mods == 1 && c.calls == 1);
    CHECK(run(loop).dispatched_count == 0 && !state(&f).callback_active);
    REQUIRE(vireo_connection_detach(f.connection, NULL) == VIREO_OK);
    cleanup(&f);
    REQUIRE(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
}

static void test_dependencies(int cause)
{
    fixture_t f;
    setup(&f, true);
    vireo_event_loop_t *loop = make_loop(1);
    callback_context_t c = {.fixture = &f, .loop_owner = &loop};
    vireo_connection_loop_error_t e;
    f.fail_add = cause;
    errno = E2BIG;
    CHECK(vireo_connection_attach(f.connection, loop, VIREO_EPOLL_INTEREST_WRITE,
                                    callback, &c, &e) == VIREO_RESULT_IO);
    CHECK(f.adds == 1 && !state(&f).loop_attached && errno == E2BIG);
    CHECK(e.stage == VIREO_CONNECTION_LOOP_STAGE_ATTACH);
    CHECK(e.loop_error.stage == VIREO_EVENT_LOOP_STAGE_ADD);
    CHECK(e.loop_error.epoll_error.system_errno == cause && run(loop).dispatched_count == 0);
    f.fail_add = 0;
    attach(&f, loop, VIREO_EPOLL_INTEREST_WRITE, &c);
    f.fail_mod = cause;
    CHECK(vireo_connection_set_interests(f.connection, 0, &e) == VIREO_RESULT_IO);
    CHECK(f.mods == 1 && state(&f).loop_interests == VIREO_EPOLL_INTEREST_WRITE);
    CHECK(e.stage == VIREO_CONNECTION_LOOP_STAGE_UPDATE &&
          e.loop_error.stage == VIREO_EVENT_LOOP_STAGE_MOD &&
          e.loop_error.epoll_error.system_errno == cause && errno == E2BIG);
    CHECK(run(loop).dispatched_count == 1);
    f.fail_del = cause;
    CHECK(vireo_connection_detach(f.connection, &e) == VIREO_RESULT_IO);
    CHECK(f.dels == 1 && state(&f).loop_attached && errno == E2BIG);
    CHECK(e.stage == VIREO_CONNECTION_LOOP_STAGE_DETACH &&
          e.loop_error.stage == VIREO_EVENT_LOOP_STAGE_DEL &&
          e.loop_error.epoll_error.system_errno == cause);
    vireo_connection_t *alias = f.connection;
    CHECK(vireo_connection_destroy(&f.connection, NULL) == VIREO_RESULT_BUSY);
    CHECK(f.connection == alias && fcntl(f.owned_fd, F_GETFD) >= 0);
    CHECK(run(loop).dispatched_count == 1 && c.calls == 2);
    f.fail_mod = 0;
    REQUIRE(vireo_connection_set_interests(f.connection, 0, &e) == VIREO_OK);
    check_clear(&e);
    f.fail_del = 0;
    REQUIRE(vireo_connection_detach(f.connection, &e) == VIREO_OK);
    CHECK(f.mods == 2 && f.dels == 2 && !state(&f).loop_attached);
    check_clear(&e);
    cleanup(&f);
    REQUIRE(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
}

static void test_table_full(void)
{
    fixture_t a, b;
    setup(&a, true); setup(&b, true);
    vireo_event_loop_t *loop = make_loop(1);
    callback_context_t ca = {.fixture = &a}, cb = {.fixture = &b};
    attach(&a, loop, 0, &ca);
    vireo_connection_loop_error_t error;
    errno = E2BIG;
    CHECK(vireo_connection_attach(b.connection, loop, 0, callback, &cb, &error) ==
          VIREO_RESULT_BUSY);
    CHECK(errno == E2BIG && error.stage == VIREO_CONNECTION_LOOP_STAGE_ATTACH);
    CHECK(error.loop_error.stage == VIREO_EVENT_LOOP_STAGE_NONE && !state(&b).loop_attached);
    CHECK(b.adds == 1);
    REQUIRE(vireo_connection_detach(a.connection, NULL) == VIREO_OK);
    attach(&b, loop, 0, &cb);
    REQUIRE(vireo_connection_detach(b.connection, NULL) == VIREO_OK);
    cleanup(&a); cleanup(&b);
    REQUIRE(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
}

static void test_self_detach(bool initial_failure)
{
    fixture_t f;
    setup(&f, true);
    vireo_event_loop_t *loop = make_loop(1);
    callback_context_t *c = malloc(sizeof(*c));
    REQUIRE(c != NULL);
    *c = (callback_context_t){.fixture = &f, .loop_owner = &loop,
        .action = initial_failure ? DEL_FAILURE : SELF_DETACH};
    attach(&f, loop, VIREO_EPOLL_INTEREST_READ, c);
    REQUIRE(send(f.peer, "X", 1, MSG_NOSIGNAL) == 1);
    if (initial_failure) f.fail_del = EINTR;
    CHECK(run(loop).dispatched_count == 1 && c->calls == 1 && !state(&f).callback_active);
    if (initial_failure) {
        CHECK(state(&f).loop_attached && f.dels == 1);
        f.fail_del = 0; c->action = SELF_DETACH;
        CHECK(run(loop).dispatched_count == 1 && c->calls == 2);
    }
    CHECK(!state(&f).loop_attached && !state(&f).callback_active);
    CHECK(run(loop).dispatched_count == 0);
    vireo_event_loop_handle_t old = f.last_handle;
    attach(&f, loop, VIREO_EPOLL_INTEREST_READ, c);
    CHECK(f.last_handle.token != old.token);
    size_t prior_calls = c->calls;
    CHECK(run(loop).dispatched_count == 1 && c->calls == prior_calls + 1);
    CHECK(!state(&f).loop_attached && !state(&f).callback_active);
    free(c); /* 仅在实际回调返回/成功解绑后释放；包装回调不再访问它。 */
    cleanup(&f);
    REQUIRE(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
}

static void test_nested(void)
{
    fixture_t a, b;
    setup(&a, false); setup(&b, false);
    vireo_event_loop_t *l1 = make_loop(1), *l2 = make_loop(1);
    callback_context_t ca = {.fixture = &a, .action = NEST, .nested_loop = l2};
    callback_context_t cb = {.fixture = &b, .outer = &a};
    attach(&a, l1, VIREO_EPOLL_INTEREST_WRITE, &ca);
    attach(&b, l2, VIREO_EPOLL_INTEREST_WRITE, &cb);
    CHECK(run(l1).dispatched_count == 1 && ca.calls == 1 && cb.calls == 1);
    CHECK(!state(&a).callback_active && !state(&b).callback_active);
    REQUIRE(vireo_connection_detach(a.connection, NULL) == VIREO_OK);
    REQUIRE(vireo_connection_detach(b.connection, NULL) == VIREO_OK);
    cleanup(&a); cleanup(&b);
    REQUIRE(vireo_event_loop_destroy(&l1, NULL) == VIREO_OK);
    REQUIRE(vireo_event_loop_destroy(&l2, NULL) == VIREO_OK);
}

static void test_two_connections(void)
{
    fixture_t a, b;
    setup(&a, false); setup(&b, false);
    vireo_event_loop_t *loop = make_loop(2);
    callback_context_t ca = {.fixture = &a, .action = RECEIVE_ONE};
    callback_context_t cb = {.fixture = &b, .action = RECEIVE_ONE};
    attach(&a, loop, VIREO_EPOLL_INTEREST_READ, &ca);
    attach(&b, loop, VIREO_EPOLL_INTEREST_READ, &cb);
    REQUIRE(send(a.peer, "A", 1, MSG_NOSIGNAL) == 1);
    REQUIRE(send(b.peer, "B", 1, MSG_NOSIGNAL) == 1);
    CHECK(run(loop).dispatched_count == 2);
    CHECK(ca.calls == 1 && cb.calls == 1 && ca.received[0] == 'A' && cb.received[0] == 'B');
    REQUIRE(vireo_connection_set_interests(a.connection, 0, NULL) == VIREO_OK);
    REQUIRE(send(a.peer, "C", 1, MSG_NOSIGNAL) == 1);
    REQUIRE(send(b.peer, "D", 1, MSG_NOSIGNAL) == 1);
    CHECK(run(loop).dispatched_count == 1);
    CHECK(ca.calls == 1 && cb.calls == 2 && cb.received[1] == 'D');
    REQUIRE(vireo_connection_detach(a.connection, NULL) == VIREO_OK);
    REQUIRE(vireo_connection_detach(b.connection, NULL) == VIREO_OK);
    cleanup(&a); cleanup(&b);
    REQUIRE(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
}

static void test_whole_loop_destroy(bool del_failed)
{
    fixture_t f;
    setup(&f, true);
    vireo_event_loop_t *loop = make_loop(1);
    callback_context_t c = {.fixture = &f};
    REQUIRE(send(f.peer, "READ", 4, MSG_NOSIGNAL) == 4);
    vireo_connection_receive_budget_t receive_budget = {4, 1};
    vireo_connection_receive_info_t received;
    REQUIRE(vireo_connection_receive(f.connection, &receive_budget, &received, NULL) == VIREO_OK);
    uint8_t const *view;
    size_t size;
    REQUIRE(vireo_connection_read_peek(f.connection, &view, &size) == VIREO_OK);
    REQUIRE(size == 4);
    attach(&f, loop, 0, &c);
    REQUIRE(vireo_connection_write_enqueue(f.connection, (uint8_t const *)"ABC", 3, NULL) ==
            VIREO_OK);
    if (del_failed) {
        f.fail_del = EIO;
        CHECK(vireo_connection_detach(f.connection, NULL) == VIREO_RESULT_IO);
    }
    REQUIRE(vireo_event_loop_request_stop(loop, NULL) == VIREO_OK);
    CHECK(run(loop).dispatched_count == 0 && state(&f).loop_attached);
    CHECK(vireo_connection_destroy(&f.connection, NULL) == VIREO_RESULT_BUSY);
    REQUIRE(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    CHECK(loop == NULL && state(&f).loop_attached);
    CHECK(vireo_connection_destroy(&f.connection, NULL) == VIREO_RESULT_BUSY);
    size_t dels = f.dels;
    errno = E2BIG;
    REQUIRE(vireo_connection_forget_destroyed_loop(f.connection, NULL) == VIREO_OK);
    REQUIRE(vireo_connection_forget_destroyed_loop(f.connection, NULL) == VIREO_OK);
    CHECK(errno == E2BIG && f.dels == dels && !state(&f).loop_attached);
    CHECK(state(&f).write_buffer.readable_size == 3 && memcmp(view, "READ", 4) == 0);
    vireo_connection_send_budget_t budget = {3, 1};
    vireo_connection_send_info_t info;
    REQUIRE(vireo_connection_send(f.connection, &budget, &info, NULL) == VIREO_OK);
    CHECK(info.sent_bytes == 3);
    char bytes[3];
    REQUIRE(recv(f.peer, bytes, sizeof(bytes), 0) == 3);
    CHECK(memcmp(bytes, "ABC", 3) == 0);
    cleanup(&f);
}

static void test_rebind_and_fd_reuse(void)
{
    fixture_t a, b;
    setup(&a, true);
    vireo_event_loop_t *loop = make_loop(1);
    callback_context_t ca = {.fixture = &a}, cb = {.fixture = &b, .action = RECEIVE_ONE};
    attach(&a, loop, VIREO_EPOLL_INTEREST_READ, &ca);
    vireo_event_loop_handle_t old = a.last_handle;
    REQUIRE(send(a.peer, "OLD", 3, MSG_NOSIGNAL) == 3);
    REQUIRE(vireo_connection_detach(a.connection, NULL) == VIREO_OK);
    attach(&a, loop, 0, &ca);
    CHECK(a.last_handle.token != old.token);
    vireo_event_loop_registration_t untouched;
    memset(&untouched, 0xa5, sizeof(untouched));
    vireo_event_loop_registration_t before = untouched;
    CHECK(vireo_event_loop_registration_inspect(loop, old, &untouched) == VIREO_RESULT_NOT_FOUND);
    CHECK(memcmp(&before, &untouched, sizeof(before)) == 0);
    REQUIRE(vireo_connection_detach(a.connection, NULL) == VIREO_OK);
    int old_fd = a.owned_fd;
    cleanup(&a);
    setup(&b, true);
    CHECK(b.owned_fd == old_fd); /* 当前隔离单线程夹具的真实 fd 复用。 */
    attach(&b, loop, VIREO_EPOLL_INTEREST_READ, &cb);
    CHECK(run(loop).dispatched_count == 0 && ca.calls == 0);
    REQUIRE(send(b.peer, "N", 1, MSG_NOSIGNAL) == 1);
    CHECK(run(loop).dispatched_count == 1 && cb.received[0] == 'N' && ca.calls == 0);
    REQUIRE(vireo_connection_detach(b.connection, NULL) == VIREO_OK);
    cleanup(&b);
    REQUIRE(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
}

static void test_view_and_cycles(void)
{
    fixture_t f;
    setup(&f, true);
    vireo_event_loop_t *loop = make_loop(1);
    callback_context_t c = {.fixture = &f};
    REQUIRE(send(f.peer, "READ", 4, MSG_NOSIGNAL) == 4);
    vireo_connection_receive_budget_t budget = {4, 1};
    vireo_connection_receive_info_t progress;
    REQUIRE(vireo_connection_receive(f.connection, &budget, &progress, NULL) == VIREO_OK);
    uint8_t const *view;
    size_t size;
    REQUIRE(vireo_connection_read_peek(f.connection, &view, &size) == VIREO_OK);
    REQUIRE(size == 4);
    REQUIRE(vireo_connection_write_enqueue(f.connection, (uint8_t const *)"WRITE", 5, NULL) ==
            VIREO_OK);
    for (size_t i = 0; i < 128; ++i) {
        attach(&f, loop, 0, &c);
        CHECK(vireo_connection_destroy(&f.connection, NULL) == VIREO_RESULT_BUSY);
        REQUIRE(vireo_connection_set_interests(f.connection, 0, NULL) == VIREO_OK);
        REQUIRE(vireo_connection_detach(f.connection, NULL) == VIREO_OK);
        CHECK(memcmp(view, "READ", 4) == 0 && state(&f).read_buffer.readable_size == 4);
        CHECK(state(&f).write_buffer.readable_size == 5);
        CHECK(state(&f).loop_interests == 0);
    }
    CHECK(f.adds == 128 && f.mods == 128 && f.dels == 128 && c.calls == 0);
    REQUIRE(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    cleanup(&f);
}

static void test_incomplete_seam(void)
{
    int pair[2];
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
    int original = pair[0];
    fixture_t f = {0};
    vireo_connection_options_t options = {4, 4, 8};
    for (unsigned i = 0; i < 4; ++i) {
        vireo_connection_loop_ops_t ops = {&f, add_binding, mod_binding, del_binding};
        if (i == 1) ops.add = NULL;
        if (i == 2) ops.mod = NULL;
        if (i == 3) ops.del = NULL;
        vireo_connection_error_t error;
        errno = E2BIG;
        CHECK(vireo_connection_create_with_loop_ops(&options, &pair[0], i == 0 ? NULL : &ops,
              &f.connection, &error) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(pair[0] == original && f.connection == NULL && errno == E2BIG);
        CHECK(error.stage == VIREO_CONNECTION_STAGE_NONE && error.system_errno == 0);
    }
    vireo_connection_loop_ops_t valid = {&f, add_binding, mod_binding, del_binding};
    options.read_capacity = 0;
    errno = E2BIG;
    CHECK(vireo_connection_create_with_loop_ops(&options, &pair[0], &valid,
          &f.connection, NULL) == VIREO_RESULT_RANGE);
    CHECK(pair[0] == original && f.connection == NULL && errno == E2BIG);
    REQUIRE(close(pair[0]) == 0 && close(pair[1]) == 0);
}

/**
 * @brief 统计本进程 fd，观察目录自身在两次计数中对称存在
 *
 * @return 当前 fd 条目数；临时目录句柄返回前关闭。
 *
 * @note opendir 失败立即结束，不能据未取得的目录宣称资源配对。
 */
static size_t fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    REQUIRE(directory != NULL);
    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) ++count;
    }
    REQUIRE(closedir(directory) == 0);
    return count;
}

int main(void)
{
    size_t baseline = fd_count();
    test_public_binding();
    test_parameters();
    test_repeat_and_same_mod();
    test_zero_and_null_context();
    test_callback_receive_budget();
    test_callback_update();
    test_dependencies(EINTR);
    test_dependencies(EIO);
    test_dependencies(ENOMEM);
    test_table_full();
    test_self_detach(false);
    test_self_detach(true);
    test_nested();
    test_two_connections();
    test_whole_loop_destroy(false);
    test_whole_loop_destroy(true);
    test_rebind_and_fd_reuse();
    test_view_and_cycles();
    test_incomplete_seam();
    CHECK(fd_count() == baseline);
    printf("connection loop binding: 19 groups, %u failures; fd baseline checked\n", failures);
    return failures == 0 ? 0 : 1;
}
