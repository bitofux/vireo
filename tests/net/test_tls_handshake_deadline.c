/*
- PROJECT : VIREO
- FILE    : test_tls_handshake_deadline.c
- AUTHOR  : bitofux
- DATE    : 2026-10-17
- BRIEF   : 此模块负责：
- -- 固定握手总期限、旧入口防绕过、真实双端与首次前超时验证
 */
#define _GNU_SOURCE
#include "tls_connection_internal.h"
#include "tls_context_fixtures.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#define CHECK(condition) do { if (!(condition)) { \
    (void)fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); abort(); \
} } while (0)
#define EXPECT(expression, expected) do { errno = ECHILD; \
    vireo_result_t actual = (expression); CHECK(actual == (expected)); CHECK(errno == ECHILD); \
} while (0)

/** 同一枚举开销在前后相同；只作为本次有限fd配对证据。 */
static size_t fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd"); CHECK(directory != NULL);
    size_t count = 0; struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) { ++count; }
    }
    CHECK(closedir(directory) == 0); return count;
}

/** 无部署材料或外网；长链只为受限socket缓冲的真实WANT_WRITE制造数据量。 */
static vireo_tls_context_t *make_context(size_t extra_roots)
{
    size_t leaf_size = sizeof(fixture_leaf) - 1;
    size_t root_size = sizeof(fixture_root) - 1;
    CHECK(extra_roots <= 128);
    size_t bytes = leaf_size + extra_roots * root_size;
    unsigned char *chain = malloc(bytes); CHECK(chain != NULL);
    memcpy(chain, fixture_leaf, leaf_size);
    for (size_t i = 0; i < extra_roots; ++i) {
        memcpy(chain + leaf_size + i * root_size, fixture_root, root_size);
    }
    vireo_tls_context_options_t options = {chain, bytes, fixture_key, sizeof(fixture_key) - 1, 4096};
    vireo_tls_context_t *context = NULL;
    EXPECT(vireo_tls_context_create_server(&options, &context, NULL), VIREO_OK);
    free(chain); /* context不借源PEM到返回之后。 */
    return context;
}

/** 真实fd由夹具唯一拥有，context包装提前释放以持续验证SSL内部引用。 */
static vireo_tls_connection_t *make_server(int pair[2], size_t roots)
{
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
    vireo_tls_context_t *context = make_context(roots);
    vireo_tls_connection_options_t options = {4096};
    vireo_tls_connection_t *server = NULL;
    EXPECT(vireo_tls_connection_create_server(context, &options, pair[0], &server, NULL), VIREO_OK);
    EXPECT(vireo_tls_context_destroy(&context, NULL), VIREO_OK);
    return server;
}

/** 先TLS后fd，不接受隐式close或重复close。 */
static void release_server(vireo_tls_connection_t **server, int pair[2])
{
    EXPECT(vireo_tls_connection_destroy(server, NULL), VIREO_OK);
    CHECK(fcntl(pair[0], F_GETFD) != -1);
    CHECK(close(pair[0]) == 0);
    if (pair[1] >= 0) { CHECK(close(pair[1]) == 0); }
}

/** 成功/WANT须完整清独立诊断；不把errno当返回原因。 */
static void clean_error(vireo_tls_connection_error_t const *error)
{
    CHECK(error->stage == VIREO_TLS_CONNECTION_STAGE_NONE && error->system_errno == 0);
    CHECK(error->openssl_error_code == 0 && !error->has_more_errors);
}

/** 逐步控制原生结果和调用计数；不改变全局时钟/信号策略。 */
typedef struct script {
    int classification;
    int native_errno;
    unsigned int errors;
    bool ignored;
    bool query_fails;
    size_t queries;
    size_t calls;
    size_t classifications;
} script_t;

static int scripted_policy(void *context, bool *out_ignored)
{
    script_t *script = context; ++script->queries;
    if (script->query_fails) { errno = EINTR; return -1; }
    *out_ignored = script->ignored; return 0;
}

static int scripted_handshake(void *context, SSL *native)
{
    script_t *script = context; CHECK(native != NULL && errno == 0 && ERR_peek_error() == 0);
    ++script->calls;
    if (script->errors != 0) { ERR_raise(ERR_LIB_USER, 444); }
    if (script->errors == 2) { ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE); }
    errno = script->native_errno; return -1;
}

static int scripted_error(void *context, SSL *native, int returned)
{
    script_t *script = context; CHECK(native != NULL && returned == -1);
    CHECK(script->calls == script->classifications + 1); ++script->classifications;
    errno = ENOTTY; return script->classification;
}

static vireo_tls_handshake_ops_t script_ops(script_t *script)
{
    vireo_tls_handshake_ops_t ops = {script, scripted_policy, scripted_handshake, scripted_error};
    return ops;
}

static vireo_tls_handshake_deadline_info_t deadline_info(vireo_tls_connection_t *server)
{
    vireo_tls_handshake_deadline_info_t info;
    EXPECT(vireo_tls_connection_handshake_deadline_inspect(server, &info, NULL), VIREO_OK);
    return info;
}

static void timeout_report(vireo_tls_handshake_info_t const *info,
    vireo_tls_connection_error_t const *error)
{
    CHECK(info->state == VIREO_TLS_HANDSHAKE_FAILED && info->wait == VIREO_TLS_HANDSHAKE_WAIT_NONE);
    CHECK(!info->native_called && error->stage == VIREO_TLS_CONNECTION_STAGE_DEADLINE);
    CHECK(error->system_errno == 0 && error->openssl_error_code == 0 && !error->has_more_errors);
    CHECK(ERR_peek_error() == 0);
}

/** 基本参数拒绝保持旧库队列/全部输出，完整表检查先于终态或期限。 */
static void arguments_and_tables(void)
{
    int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
    script_t script = {0}; vireo_tls_handshake_ops_t ops = script_ops(&script);
    vireo_tls_handshake_info_t step; memset(&step, 0xA3, sizeof(step));
    unsigned char saved[sizeof(step)]; memcpy(saved, &step, sizeof(saved));
    vireo_tls_handshake_deadline_info_t view; memset(&view, 0xB5, sizeof(view));
    unsigned char old_view[sizeof(view)]; memcpy(old_view, &view, sizeof(view));
    vireo_tls_connection_error_t error;
    ERR_raise(ERR_LIB_USER, 771); unsigned long old_error = ERR_peek_error();
    EXPECT(vireo_tls_connection_handshake_deadline_arm(NULL, 0, 0, &error), VIREO_RESULT_INVALID_ARGUMENT);
    clean_error(&error);
    EXPECT(vireo_tls_connection_handshake_deadline_inspect(NULL, &view, &error), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tls_connection_handshake_deadline_inspect(server, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tls_connection_handshake_step_at(NULL, 0, &step, &error), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tls_connection_handshake_step_at(server, 0, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    for (unsigned int i = 0; i < 4; ++i) {
        vireo_tls_handshake_ops_t bad = ops;
        if (i == 1) { bad.sigpipe_ignored = NULL; }
        if (i == 2) { bad.do_handshake = NULL; }
        if (i == 3) { bad.get_error = NULL; }
        EXPECT(vireo_tls_connection_handshake_at_with_ops(server, 0, &step, &error, i == 0 ? NULL : &bad),
            VIREO_RESULT_INVALID_ARGUMENT);
        clean_error(&error);
    }
    CHECK(memcmp(saved, &step, sizeof(step)) == 0 && memcmp(old_view, &view, sizeof(view)) == 0);
    CHECK(ERR_peek_error() == old_error && script.queries == 0 && script.calls == 0);
    ERR_clear_error();
    EXPECT(vireo_tls_connection_handshake_deadline_arm(server, 0, 0, NULL), VIREO_OK);
    EXPECT(vireo_tls_connection_handshake_at_with_ops(server, 0, &step, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(server->state == VIREO_TLS_HANDSHAKE_INITIAL);
    release_server(&server, pair);
}

/** 两条模式只在初态选择；旧对象不必迁移，实际sizeof仍由显式预算约束。 */
static void arm_and_legacy_modes(void)
{
    int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
    vireo_tls_handshake_deadline_info_t info = deadline_info(server);
    CHECK(!info.armed && info.deadline_ns == 0 && info.last_now_ns == 0);
    script_t script = {.ignored = true, .classification = SSL_ERROR_WANT_READ};
    vireo_tls_handshake_ops_t ops = script_ops(&script);
    vireo_tls_handshake_info_t step; memset(&step, 0xAA, sizeof(step));
    unsigned char saved[sizeof(step)]; memcpy(saved, &step, sizeof(saved));
    EXPECT(vireo_tls_connection_handshake_at_with_ops(server, 0, &step, NULL, &ops), VIREO_RESULT_BUSY);
    CHECK(memcmp(saved, &step, sizeof(step)) == 0 && script.queries == 0);
    EXPECT(vireo_tls_connection_handshake_with_ops(server, &step, NULL, &ops), VIREO_OK);
    CHECK(step.native_called && script.calls == 1 && server->handshake_native_attempted);
    vireo_tls_connection_t original = *server;
    EXPECT(vireo_tls_connection_handshake_deadline_arm(server, 10, 20, NULL), VIREO_RESULT_BUSY);
    CHECK(memcmp(&original, server, sizeof(original)) == 0);
    EXPECT(vireo_tls_connection_handshake_with_ops(server, &step, NULL, &ops), VIREO_OK);
    CHECK(script.calls == 2 && !deadline_info(server).armed);
    vireo_tls_context_t *context = make_context(0);
    vireo_tls_connection_t *candidate = NULL;
    vireo_tls_connection_options_t options = {sizeof(*server) - 1};
    EXPECT(vireo_tls_connection_create_server(context, &options, pair[0], &candidate, NULL), VIREO_RESULT_RANGE);
    CHECK(candidate == NULL);
    EXPECT(vireo_tls_context_destroy(&context, NULL), VIREO_OK);
    release_server(&server, pair);
}

/** READ/WRITE变化和少量进展不能续期；旧入口和重新arm不能绕过门禁。 */
static void fixed_deadline_and_directions(void)
{
    int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
    EXPECT(vireo_tls_connection_handshake_deadline_arm(server, 10, 30, NULL), VIREO_OK);
    script_t script = {.ignored = true}; vireo_tls_handshake_ops_t ops = script_ops(&script);
    vireo_monotonic_ns_t times[] = {10, 20, 29, 29};
    vireo_tls_handshake_info_t step; vireo_tls_connection_error_t error;
    for (size_t i = 0; i < 4; ++i) {
        script.classification = i == 1 ? SSL_ERROR_WANT_WRITE : SSL_ERROR_WANT_READ;
        ERR_raise(ERR_LIB_USER, 888);
        EXPECT(vireo_tls_connection_handshake_at_with_ops(server, times[i], &step, &error, &ops), VIREO_OK);
        clean_error(&error); CHECK(ERR_peek_error() == 0 && step.native_called);
        CHECK(step.wait == (i == 1 ? VIREO_TLS_HANDSHAKE_WAIT_WRITE : VIREO_TLS_HANDSHAKE_WAIT_READ));
        CHECK(script.calls == i + 1 && script.classifications == i + 1);
        vireo_tls_handshake_deadline_info_t info = deadline_info(server);
        CHECK(info.armed && info.deadline_ns == 30 && info.last_now_ns == times[i]);
    }
    vireo_tls_connection_t original = *server;
    memset(&step, 0xC7, sizeof(step)); unsigned char saved[sizeof(step)]; memcpy(saved, &step, sizeof(saved));
    EXPECT(vireo_tls_connection_handshake_step(server, &step, &error), VIREO_RESULT_BUSY); clean_error(&error);
    EXPECT(vireo_tls_connection_handshake_with_ops(server, &step, NULL, &ops), VIREO_RESULT_BUSY);
    EXPECT(vireo_tls_connection_handshake_deadline_arm(server, 29, 1000, NULL), VIREO_RESULT_BUSY);
    EXPECT(vireo_tls_connection_handshake_at_with_ops(server, 28, &step, &error, &ops), VIREO_RESULT_RANGE);
    clean_error(&error);
    CHECK(memcmp(saved, &step, sizeof(step)) == 0 && memcmp(&original, server, sizeof(original)) == 0);
    script.ignored = false; script.query_fails = true;
    EXPECT(vireo_tls_connection_handshake_at_with_ops(server, 30, &step, &error, &ops), VIREO_RESULT_TIMEOUT);
    timeout_report(&step, &error); CHECK(script.queries == 4 && script.calls == 4);
    vireo_tls_connection_info_t observed;
    EXPECT(vireo_tls_connection_inspect(server, &observed, NULL), VIREO_OK);
    CHECK(observed.handshake_started && !observed.handshake_complete);
    CHECK(deadline_info(server).last_now_ns == 30);
    release_server(&server, pair);
}

/** 0/MAX是有限合法值；首次前超时不伪造started，首错与期限历史永久保持。 */
static void zero_and_max_timeout_cache(void)
{
    struct times { vireo_monotonic_ns_t start, due, expire; } const cases[] = {
        {0, 0, 0}, {100, 50, 100}, {UINT64_MAX, UINT64_MAX, UINT64_MAX}, {0, UINT64_MAX, UINT64_MAX}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
        script_t script = {.query_fails = true}; vireo_tls_handshake_ops_t ops = script_ops(&script);
        EXPECT(vireo_tls_connection_handshake_deadline_arm(server, cases[i].start, cases[i].due, NULL), VIREO_OK);
        CHECK(server->state == VIREO_TLS_HANDSHAKE_INITIAL);
        vireo_tls_handshake_info_t step; vireo_tls_connection_error_t error;
        ERR_raise(ERR_LIB_USER, 900);
        EXPECT(vireo_tls_connection_handshake_at_with_ops(server, cases[i].expire, &step, &error, &ops), VIREO_RESULT_TIMEOUT);
        timeout_report(&step, &error);
        vireo_tls_connection_info_t info;
        EXPECT(vireo_tls_connection_inspect(server, &info, NULL), VIREO_OK);
        CHECK(!info.handshake_started && !info.handshake_complete && info.handshake_state == VIREO_TLS_HANDSHAKE_FAILED);
        vireo_tls_connection_t original = *server;
        EXPECT(vireo_tls_connection_handshake_deadline_arm(server, 0, UINT64_MAX, NULL), VIREO_RESULT_BUSY);
        for (size_t k = 0; k < 3; ++k) {
            ERR_raise(ERR_LIB_USER, 901);
            EXPECT(vireo_tls_connection_handshake_step_at(server, k == 0 ? 0 : UINT64_MAX, &step, &error), VIREO_RESULT_TIMEOUT);
            timeout_report(&step, &error);
            EXPECT(vireo_tls_connection_handshake_step(server, &step, &error), VIREO_RESULT_TIMEOUT);
            timeout_report(&step, &error);
            EXPECT(vireo_tls_connection_handshake_at_with_ops(server, 0, &step, &error, &ops), VIREO_RESULT_TIMEOUT);
        }
        CHECK(script.calls == 0 && script.queries == 0 && script.classifications == 0);
        CHECK(memcmp(&original, server, sizeof(original)) == 0);
        vireo_tls_handshake_deadline_info_t timing = deadline_info(server);
        CHECK(timing.armed && timing.deadline_ns == cases[i].due && timing.last_now_ns == cases[i].expire);
        vireo_tls_io_options_t options = {32, 32, 32832, 1, 0, 32, 0, 32};
        EXPECT(vireo_tls_connection_io_configure(server, &options, NULL), VIREO_RESULT_BUSY);
        release_server(&server, pair);
    }
}

/** 前置拒绝不能推进时间，修复后允许使用晚于已提交值的now；到期优先于策略。 */
static void policy_and_time_recovery(void)
{
    int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
    EXPECT(vireo_tls_connection_handshake_deadline_arm(server, 100, 200, NULL), VIREO_OK);
    script_t script = {.classification = SSL_ERROR_WANT_READ};
    vireo_tls_handshake_ops_t ops = script_ops(&script);
    vireo_tls_connection_t original = *server;
    vireo_tls_handshake_info_t step; memset(&step, 0xAF, sizeof(step));
    unsigned char saved[sizeof(step)]; memcpy(saved, &step, sizeof(saved));
    vireo_tls_connection_error_t error;
    EXPECT(vireo_tls_connection_handshake_at_with_ops(server, 150, &step, &error, &ops), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(error.stage == VIREO_TLS_CONNECTION_STAGE_SIGNAL_POLICY && error.system_errno == 0);
    script.query_fails = true;
    EXPECT(vireo_tls_connection_handshake_at_with_ops(server, 151, &step, &error, &ops), VIREO_RESULT_IO);
    CHECK(error.system_errno == EINTR && script.calls == 0 && script.queries == 2);
    CHECK(memcmp(saved, &step, sizeof(step)) == 0 && memcmp(&original, server, sizeof(original)) == 0);
    script.query_fails = false; script.ignored = true;
    EXPECT(vireo_tls_connection_handshake_at_with_ops(server, 120, &step, &error, &ops), VIREO_OK);
    CHECK(deadline_info(server).last_now_ns == 120 && script.calls == 1);
    original = *server; memcpy(saved, &step, sizeof(saved));
    EXPECT(vireo_tls_connection_handshake_at_with_ops(server, 119, &step, &error, &ops), VIREO_RESULT_RANGE);
    clean_error(&error);
    CHECK(memcmp(saved, &step, sizeof(step)) == 0 && memcmp(&original, server, sizeof(original)) == 0);
    script.query_fails = true; script.ignored = false;
    EXPECT(vireo_tls_connection_handshake_at_with_ops(server, 200, &step, &error, &ops), VIREO_RESULT_TIMEOUT);
    timeout_report(&step, &error); CHECK(script.queries == 3 && script.calls == 1);
    release_server(&server, pair);
}

/** 原生首错不被到期/回退覆盖；带时间路径仍保存即时errno及独立库原因。 */
static void native_first_error_priority(void)
{
    int classifications[] = {SSL_ERROR_SYSCALL, SSL_ERROR_SSL, SSL_ERROR_SSL, SSL_ERROR_WANT_ASYNC};
    vireo_result_t results[] = {VIREO_RESULT_IO, VIREO_RESULT_PROTOCOL, VIREO_RESULT_NO_MEMORY, VIREO_RESULT_INTERNAL};
    for (unsigned int mode = 0; mode < 2; ++mode) {
        for (size_t i = 0; i < 4; ++i) {
            int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
            if (mode == 0) { EXPECT(vireo_tls_connection_handshake_deadline_arm(server, 10, 20, NULL), VIREO_OK); }
            script_t script = {.classification = classifications[i], .native_errno = EPIPE,
                .errors = i == 0 || i == 2 ? 2U : 1U, .ignored = true};
            vireo_tls_handshake_ops_t ops = script_ops(&script);
            vireo_tls_handshake_info_t step; vireo_tls_connection_error_t error;
            if (mode == 0) {
                EXPECT(vireo_tls_connection_handshake_at_with_ops(server, 15, &step, &error, &ops), results[i]);
                CHECK(deadline_info(server).last_now_ns == 15);
            } else {
                EXPECT(vireo_tls_connection_handshake_with_ops(server, &step, &error, &ops), results[i]);
            }
            CHECK(step.native_called && error.stage == VIREO_TLS_CONNECTION_STAGE_HANDSHAKE);
            CHECK(error.system_errno == (i == 0 ? EPIPE : 0) && error.has_more_errors == (i == 0 || i == 2));
            CHECK(ERR_GET_REASON((unsigned long)error.openssl_error_code) == 444);
            vireo_tls_connection_error_t first = error;
            for (unsigned int k = 0; k < 2; ++k) {
                EXPECT(vireo_tls_connection_handshake_step_at(server, k == 0 ? 0 : UINT64_MAX, &step, &error), results[i]);
                CHECK(!step.native_called && error.stage == first.stage && error.system_errno == first.system_errno);
                CHECK(error.openssl_error_code == first.openssl_error_code && error.has_more_errors == first.has_more_errors);
            }
            EXPECT(vireo_tls_connection_handshake_step(server, &step, NULL), results[i]);
            CHECK(script.queries == 1 && script.calls == 1 && script.classifications == 1);
            release_server(&server, pair);
        }
    }
}

/** 损坏的期限/尝试/首错组合不能成为合法生命周期；主输出与owner保持。 */
static void invalid_state_preserves_outputs(void)
{
    int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
    vireo_tls_connection_t pristine = *server;
    for (unsigned int i = 0; i < 8; ++i) {
        *server = pristine;
        if (i == 0) { server->deadline_ns = 1; }
        if (i == 1) { server->last_now_ns = 1; }
        if (i == 2) { server->handshake_native_attempted = true; }
        if (i >= 3) {
            server->state = VIREO_TLS_HANDSHAKE_FAILED;
            server->failure_result = VIREO_RESULT_TIMEOUT;
            server->failure_error.stage = VIREO_TLS_CONNECTION_STAGE_DEADLINE;
            server->deadline_ns = 20; server->last_now_ns = 20; server->deadline_armed = true;
        }
        if (i == 3) { server->deadline_armed = false; }
        if (i == 4) { server->last_now_ns = 19; }
        if (i == 5) { server->failure_error.system_errno = EPIPE; }
        if (i == 6) { server->failure_error.openssl_error_code = 1; }
        if (i == 7) { server->failure_error.has_more_errors = true; }
        vireo_tls_connection_t corrupted = *server;
        vireo_tls_handshake_deadline_info_t info; memset(&info, 0xCA, sizeof(info));
        unsigned char saved[sizeof(info)]; memcpy(saved, &info, sizeof(info));
        vireo_tls_handshake_info_t step; memset(&step, 0xCB, sizeof(step));
        unsigned char old_step[sizeof(step)]; memcpy(old_step, &step, sizeof(step));
        vireo_tls_connection_error_t error;
        EXPECT(vireo_tls_connection_handshake_deadline_inspect(server, &info, &error), VIREO_RESULT_INTERNAL);
        CHECK(error.stage == VIREO_TLS_CONNECTION_STAGE_INSPECT && memcmp(saved, &info, sizeof(info)) == 0);
        EXPECT(vireo_tls_connection_handshake_deadline_arm(server, 10, 20, NULL), VIREO_RESULT_INTERNAL);
        EXPECT(vireo_tls_connection_handshake_step_at(server, 20, &step, NULL), VIREO_RESULT_INTERNAL);
        CHECK(memcmp(old_step, &step, sizeof(step)) == 0 && memcmp(&corrupted, server, sizeof(corrupted)) == 0);
    }
    *server = pristine; release_server(&server, pair);
}

typedef struct peer_fixture {
    int pair[2];                       /**< 夹具唯一拥有，TLS只借用各自一端。 */
    vireo_tls_connection_t *server;     /**< 服务器公共owner，所有访问同线程。 */
    SSL *client;                        /**< 测试客户端native owner，NOCLOSE BIO。 */
    bool client_done;                   /**< 客户端真实完成状态，驱动后提交。 */
    bool client_failed;                 /**< 客户端致命失败，不再继续其I/O。 */
    vireo_tls_handshake_wait_t client_wait; /**< 客户端当前需要方向。 */
    size_t read_waits;                  /**< 服务器实际WANT_READ观测数。 */
    size_t write_waits;                 /**< 服务器实际WANT_WRITE观测数。 */
} peer_fixture_t;

/** 客户端信任专用根并验证SAN；固定验证时间仅让公开测试证书不依赖运行日期。 */
static peer_fixture_t make_peer(size_t roots, bool trusted, char const *host, bool tls12)
{
    peer_fixture_t fixture = {0}; fixture.server = make_server(fixture.pair, roots);
    SSL_CTX *context = SSL_CTX_new(TLS_client_method()); CHECK(context != NULL);
    CHECK(SSL_CTX_set_min_proto_version(context, tls12 ? TLS1_2_VERSION : TLS1_3_VERSION) == 1);
    CHECK(SSL_CTX_set_max_proto_version(context, tls12 ? TLS1_2_VERSION : TLS1_3_VERSION) == 1);
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
    if (trusted) {
        BIO *bio = BIO_new_mem_buf(fixture_root, (int)(sizeof(fixture_root) - 1)); CHECK(bio != NULL);
        X509 *root = PEM_read_bio_X509(bio, NULL, NULL, NULL); CHECK(root != NULL);
        CHECK(X509_STORE_add_cert(SSL_CTX_get_cert_store(context), root) == 1);
        X509_free(root); CHECK(BIO_free(bio) == 1);
    }
    fixture.client = SSL_new(context); CHECK(fixture.client != NULL); SSL_CTX_free(context);
    X509_VERIFY_PARAM_set_time(SSL_get0_param(fixture.client), (time_t)1800000000);
    CHECK(SSL_set1_host(fixture.client, host) == 1);
    BIO *bio = BIO_new_socket(fixture.pair[1], BIO_NOCLOSE); CHECK(bio != NULL);
    SSL_set_bio(fixture.client, bio, bio); SSL_set_connect_state(fixture.client);
    return fixture;
}

static void release_peer(peer_fixture_t *fixture)
{
    SSL_free(fixture->client); fixture->client = NULL;
    release_server(&fixture->server, fixture->pair);
}

/** 真实客户端与生产一样紧邻分类，但不使用服务端测试缝代替网络。 */
static void client_step(peer_fixture_t *fixture)
{
    CHECK(!fixture->client_done && !fixture->client_failed);
    ERR_clear_error(); errno = 0;
    int returned = SSL_do_handshake(fixture->client);
    int classification = returned <= 0 ? SSL_get_error(fixture->client, returned) : SSL_ERROR_NONE;
    if (returned == 1) {
        CHECK(SSL_is_init_finished(fixture->client) == 1);
        fixture->client_done = true; fixture->client_wait = VIREO_TLS_HANDSHAKE_WAIT_NONE;
    } else if (classification == SSL_ERROR_WANT_READ || classification == SSL_ERROR_WANT_WRITE) {
        fixture->client_wait = classification == SSL_ERROR_WANT_READ ?
            VIREO_TLS_HANDSHAKE_WAIT_READ : VIREO_TLS_HANDSHAKE_WAIT_WRITE;
    } else { fixture->client_failed = true; }
    ERR_clear_error();
}

/** 真实可信协商由caller读base clock，期限裁剪poll，超时醒来也执行时间门禁。 */
static void real_verified_and_application(void)
{
    peer_fixture_t fixture = make_peer(0, true, "vireo-034-test.invalid", false);
    vireo_monotonic_ns_t now, due;
    EXPECT(vireo_clock_monotonic_now(&now, NULL), VIREO_OK);
    EXPECT(vireo_clock_deadline_after(now, UINT64_C(5000000000), &due), VIREO_OK);
    EXPECT(vireo_tls_connection_handshake_deadline_arm(fixture.server, now, due, NULL), VIREO_OK);
    vireo_tls_handshake_info_t step;
    EXPECT(vireo_tls_connection_handshake_step_at(fixture.server, now, &step, NULL), VIREO_OK);
    CHECK(step.native_called && step.wait == VIREO_TLS_HANDSHAKE_WAIT_READ);
    client_step(&fixture);
    for (size_t round = 0; round < 2048 && (!fixture.client_done || step.state != VIREO_TLS_HANDSHAKE_ESTABLISHED); ++round) {
        EXPECT(vireo_clock_monotonic_now(&now, NULL), VIREO_OK);
        int wait_ms;
        EXPECT(vireo_clock_deadline_wait_ms(now, due, 50, &wait_ms), VIREO_OK);
        struct pollfd fds[2] = {
            {step.state == VIREO_TLS_HANDSHAKE_ESTABLISHED ? -1 : fixture.pair[0],
                step.wait == VIREO_TLS_HANDSHAKE_WAIT_WRITE ? POLLOUT : POLLIN, 0},
            {fixture.client_done || fixture.client_failed ? -1 : fixture.pair[1],
                fixture.client_wait == VIREO_TLS_HANDSHAKE_WAIT_WRITE ? POLLOUT : POLLIN, 0}
        };
        int polled = poll(fds, 2, wait_ms); CHECK(polled >= 0 || errno == EINTR);
        EXPECT(vireo_clock_monotonic_now(&now, NULL), VIREO_OK);
        if (step.state != VIREO_TLS_HANDSHAKE_ESTABLISHED && (polled <= 0 || fds[0].revents != 0 || now >= due)) {
            EXPECT(vireo_tls_connection_handshake_step_at(fixture.server, now, &step, NULL), VIREO_OK);
        }
        if (polled > 0 && fds[1].revents != 0) { client_step(&fixture); }
        CHECK(!fixture.client_failed && now < due);
    }
    CHECK(fixture.client_done && step.state == VIREO_TLS_HANDSHAKE_ESTABLISHED);
    CHECK(SSL_get_verify_result(fixture.client) == X509_V_OK && SSL_version(fixture.client) == TLS1_3_VERSION);
    vireo_tls_handshake_deadline_info_t timing = deadline_info(fixture.server);
    CHECK(timing.armed && timing.deadline_ns == due && timing.last_now_ns < due);
    vireo_tls_connection_info_t history;
    EXPECT(vireo_tls_connection_inspect(fixture.server, &history, NULL), VIREO_OK);
    CHECK(history.handshake_started && history.handshake_complete);
    EXPECT(vireo_tls_connection_handshake_step_at(fixture.server, UINT64_MAX, &step, NULL), VIREO_OK);
    CHECK(!step.native_called && deadline_info(fixture.server).last_now_ns == timing.last_now_ns);
    EXPECT(vireo_tls_connection_handshake_step(fixture.server, &step, NULL), VIREO_OK);
    EXPECT(vireo_tls_connection_handshake_deadline_arm(fixture.server, 0, UINT64_MAX, NULL), VIREO_RESULT_BUSY);

    /* 历史握手期限不能限制应用收发；观察入口不结束已有明文view。 */
    vireo_tls_io_options_t options = {4096, 4096, 40960, 1, 0, 4096, 0, 4096};
    EXPECT(vireo_tls_connection_io_configure(fixture.server, &options, NULL), VIREO_OK);
    size_t written = 0;
    ERR_clear_error(); CHECK(SSL_write_ex(fixture.client, "abc", 3, &written) == 1 && written == 3);
    vireo_tls_io_budget_t budget = {4096, 4}; vireo_tls_io_progress_t progress;
    EXPECT(vireo_tls_connection_receive(fixture.server, &budget, &progress, NULL), VIREO_OK);
    CHECK(progress.bytes == 3);
    uint8_t const *view; size_t size;
    EXPECT(vireo_tls_connection_read_peek(fixture.server, &view, &size, NULL), VIREO_OK);
    CHECK(size == 3 && memcmp(view, "abc", 3) == 0);
    EXPECT(vireo_tls_connection_handshake_step_at(fixture.server, 0, &step, NULL), VIREO_OK);
    EXPECT(vireo_tls_connection_handshake_deadline_inspect(fixture.server, &timing, NULL), VIREO_OK);
    CHECK(memcmp(view, "abc", 3) == 0);
    EXPECT(vireo_tls_connection_read_consume(fixture.server, size, NULL), VIREO_OK);
    uint8_t const response[] = {'r', 'e', 'p', 'l', 'y'};
    EXPECT(vireo_tls_connection_enqueue(fixture.server, response, sizeof(response), NULL), VIREO_OK);
    EXPECT(vireo_tls_connection_send(fixture.server, &budget, &progress, NULL), VIREO_OK);
    CHECK(progress.bytes == 5);
    unsigned char bytes[16]; size_t read_size = 0;
    ERR_clear_error(); CHECK(SSL_read_ex(fixture.client, bytes, sizeof(bytes), &read_size) == 1);
    CHECK(read_size == 5 && memcmp(bytes, "reply", 5) == 0);
    (void)puts("real trusted TLS1.3 with base-clock deadline completed; application abc/reply preserved");
    release_peer(&fixture);
}

/** 真实空socket产生WANT，显式推进时间而不sleep；迟到ClientHello不能复活。 */
static void real_silent_and_late_client(void)
{
    peer_fixture_t fixture = make_peer(0, true, "vireo-034-test.invalid", false);
    int flags = fcntl(fixture.pair[0], F_GETFL), descriptor = fcntl(fixture.pair[0], F_GETFD);
    EXPECT(vireo_tls_connection_handshake_deadline_arm(fixture.server, 10, 20, NULL), VIREO_OK);
    vireo_tls_handshake_info_t step; vireo_tls_connection_error_t error;
    EXPECT(vireo_tls_connection_handshake_step_at(fixture.server, 10, &step, NULL), VIREO_OK);
    CHECK(step.native_called && step.wait == VIREO_TLS_HANDSHAKE_WAIT_READ);
    EXPECT(vireo_tls_connection_handshake_step_at(fixture.server, 19, &step, NULL), VIREO_OK);
    CHECK(step.native_called && deadline_info(fixture.server).deadline_ns == 20);
    struct pollfd ready = {fixture.pair[0], POLLIN, 0}; CHECK(poll(&ready, 1, 0) == 0);
    EXPECT(vireo_tls_connection_handshake_step_at(fixture.server, 20, &step, &error), VIREO_RESULT_TIMEOUT);
    timeout_report(&step, &error);
    client_step(&fixture); CHECK(!fixture.client_failed);
    ready.revents = 0; CHECK(poll(&ready, 1, 0) == 1 && (ready.revents & POLLIN) != 0);
    EXPECT(vireo_tls_connection_handshake_step_at(fixture.server, 21, &step, &error), VIREO_RESULT_TIMEOUT);
    timeout_report(&step, &error);
    EXPECT(vireo_tls_connection_handshake_step(fixture.server, &step, &error), VIREO_RESULT_TIMEOUT);
    timeout_report(&step, &error);
    CHECK(fcntl(fixture.pair[0], F_GETFL) == flags && fcntl(fixture.pair[0], F_GETFD) == descriptor);
    (void)puts("real silent peer WANT_READ then TIMEOUT at equality without new fd event; late ClientHello rejected");
    release_peer(&fixture);
}

/** 真实长链/小发送缓冲产生WANT_WRITE；到期清等待且不继续原生发送。 */
static void real_write_wait_timeout(void)
{
    peer_fixture_t fixture = make_peer(128, true, "vireo-034-test.invalid", false);
    int bytes = 1024; CHECK(setsockopt(fixture.pair[0], SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes)) == 0);
    EXPECT(vireo_tls_connection_handshake_deadline_arm(fixture.server, 10, 20, NULL), VIREO_OK);
    client_step(&fixture);
    vireo_tls_handshake_info_t step; vireo_tls_connection_error_t error;
    EXPECT(vireo_tls_connection_handshake_step_at(fixture.server, 10, &step, NULL), VIREO_OK);
    CHECK(step.native_called && step.wait == VIREO_TLS_HANDSHAKE_WAIT_WRITE);
    EXPECT(vireo_tls_connection_handshake_step_at(fixture.server, 20, &step, &error), VIREO_RESULT_TIMEOUT);
    timeout_report(&step, &error);
    vireo_tls_connection_info_t history;
    EXPECT(vireo_tls_connection_inspect(fixture.server, &history, NULL), VIREO_OK);
    CHECK(history.handshake_started && !history.handshake_complete);
    (void)puts("real WANT_WRITE -> permanent TIMEOUT; wait cleared");
    release_peer(&fixture);
}

/** 真实原生协议首错发生在期限前，晚到的时间不会把它改写成TIMEOUT。 */
static void real_protocol_first_error(void)
{
    int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
    EXPECT(vireo_tls_connection_handshake_deadline_arm(server, 10, 20, NULL), VIREO_OK);
    CHECK(send(pair[1], "plain-text", 10, MSG_NOSIGNAL) == 10);
    vireo_tls_handshake_info_t step; vireo_tls_connection_error_t error;
    EXPECT(vireo_tls_connection_handshake_step_at(server, 15, &step, &error), VIREO_RESULT_PROTOCOL);
    CHECK(step.native_called && error.stage == VIREO_TLS_CONNECTION_STAGE_HANDSHAKE && error.openssl_error_code != 0);
    vireo_tls_connection_error_t first = error;
    EXPECT(vireo_tls_connection_handshake_step_at(server, 20, &step, &error), VIREO_RESULT_PROTOCOL);
    CHECK(!step.native_called && error.stage == first.stage && error.openssl_error_code == first.openssl_error_code);
    EXPECT(vireo_tls_connection_handshake_step_at(server, 0, &step, &error), VIREO_RESULT_PROTOCOL);
    CHECK(!step.native_called && deadline_info(server).last_now_ns == 15);
    release_server(&server, pair);
}

/** exec专用默认信号/屏蔽pending环境；到期不要求SIG_IGN且不改变任何信号状态。 */
static int policy_child(void)
{
    struct sigaction action = {0}; action.sa_handler = SIG_DFL; CHECK(sigemptyset(&action.sa_mask) == 0);
    CHECK(sigaction(SIGPIPE, &action, NULL) == 0);
    sigset_t mask; CHECK(sigemptyset(&mask) == 0 && sigaddset(&mask, SIGPIPE) == 0);
    CHECK(sigprocmask(SIG_BLOCK, &mask, NULL) == 0 && raise(SIGPIPE) == 0);
    size_t before = fd_count(); int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
    EXPECT(vireo_tls_connection_handshake_deadline_arm(server, 10, 20, NULL), VIREO_OK);
    vireo_tls_handshake_info_t step; memset(&step, 0xAC, sizeof(step));
    unsigned char saved[sizeof(step)]; memcpy(saved, &step, sizeof(step));
    vireo_tls_connection_error_t error;
    EXPECT(vireo_tls_connection_handshake_step_at(server, 15, &step, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(error.stage == VIREO_TLS_CONNECTION_STAGE_SIGNAL_POLICY && memcmp(saved, &step, sizeof(step)) == 0);
    CHECK(deadline_info(server).last_now_ns == 10);
    EXPECT(vireo_tls_connection_handshake_step_at(server, 20, &step, &error), VIREO_RESULT_TIMEOUT);
    timeout_report(&step, &error);
    vireo_tls_connection_info_t info;
    EXPECT(vireo_tls_connection_inspect(server, &info, NULL), VIREO_OK);
    CHECK(!info.handshake_started);
    struct sigaction after; CHECK(sigaction(SIGPIPE, NULL, &after) == 0 && after.sa_handler == SIG_DFL);
    sigset_t pending, current;
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 1);
    CHECK(sigprocmask(SIG_BLOCK, NULL, &current) == 0 && sigismember(&current, SIGPIPE) == 1);
    release_server(&server, pair); CHECK(fd_count() == before);
    (void)puts("[PASS] real pre-native TIMEOUT preserves default handler, blocked mask and pending SIGPIPE");
    return 0;
}

static void run_exec(char const *mode)
{
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) { execl("/proc/self/exe", "vireo_tls_handshake_deadline_test", mode, (char *)NULL); _exit(127); }
    int status; pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited == -1 && errno == EINTR);
    CHECK(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static int real_child(void)
{
    struct sigaction action = {0}; action.sa_handler = SIG_IGN; CHECK(sigemptyset(&action.sa_mask) == 0);
    CHECK(sigaction(SIGPIPE, &action, NULL) == 0); size_t before = fd_count();
#define RUN(function) do { function(); (void)puts("[PASS] " #function); } while (0)
    RUN(real_verified_and_application);
    RUN(real_silent_and_late_client);
    RUN(real_write_wait_timeout);
    RUN(real_protocol_first_error);
#undef RUN
    CHECK(fd_count() == before); (void)printf("4 real groups passed; fd %zu -> %zu\n", before, fd_count());
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--real") == 0) { return real_child(); }
    if (argc == 2 && strcmp(argv[1], "--policy") == 0) { return policy_child(); }
    CHECK(argc == 1); size_t before = fd_count();
    struct sigaction initial, after; sigset_t initial_mask, final_mask, initial_pending, final_pending;
    CHECK(sigaction(SIGPIPE, NULL, &initial) == 0 && sigprocmask(SIG_BLOCK, NULL, &initial_mask) == 0);
    CHECK(sigpending(&initial_pending) == 0);
#define RUN(function) do { function(); (void)puts("[PASS] " #function); } while (0)
    RUN(arguments_and_tables);
    RUN(arm_and_legacy_modes);
    RUN(fixed_deadline_and_directions);
    RUN(zero_and_max_timeout_cache);
    RUN(policy_and_time_recovery);
    RUN(native_first_error_priority);
    RUN(invalid_state_preserves_outputs);
#undef RUN
    run_exec("--policy"); run_exec("--real");
    CHECK(sigaction(SIGPIPE, NULL, &after) == 0 && after.sa_handler == initial.sa_handler);
    CHECK(sigprocmask(SIG_BLOCK, NULL, &final_mask) == 0 && sigpending(&final_pending) == 0);
    CHECK(sigismember(&initial_mask, SIGPIPE) == sigismember(&final_mask, SIGPIPE));
    CHECK(sigismember(&initial_pending, SIGPIPE) == sigismember(&final_pending, SIGPIPE));
    CHECK(fd_count() == before);
    (void)printf("12 groups passed (7 own + 5 real exec); fd %zu -> %zu; parent SIGPIPE preserved\n", before, fd_count());
    return 0;
}
