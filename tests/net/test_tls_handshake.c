/*
- PROJECT : VIREO
- FILE    : test_tls_handshake.c
- AUTHOR  : bitofux
- DATE    : 2026-10-17
- BRIEF   : 此模块负责：
- -- 公共握手真实双端协作、信号隔离与逐次故障分类/终态验证
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

typedef struct script {
    int returned;              /**< 模拟原生返回，1/2用于不可能成功组合防御。 */
    int classification;        /**< 与该返回配对的可控SSL_get_error分类。 */
    int native_errno;          /**< 原生返回瞬间errno，分类故意修改它。 */
    unsigned int errors;       /**< 0无原因，1普通原因，2再附明确OOM。 */
    bool ignored;              /**< 只读策略查询的独立输出。 */
    bool query_fails;          /**< 查询失败与不符政策分别验证。 */
    size_t queries;            /**< 策略调用次数，终态重复应不再增加。 */
    size_t calls;              /**< 原生调用次数，每步最多一。 */
    size_t classifications;    /**< 失败后紧邻分类次数。 */
} script_t;

/** own只读策略缝；不修改本进程真实disposition。 */
static int scripted_policy(void *context, bool *out_ignored)
{
    script_t *script = context; ++script->queries;
    if (script->query_fails) { errno = EINTR; return -1; }
    *out_ignored = script->ignored; return 0;
}

/** 入本次模拟原生操作前必须清旧队列并将errno置0；错误在此产生。 */
static int scripted_handshake(void *context, SSL *native)
{
    script_t *script = context; CHECK(native != NULL);
    CHECK(errno == 0 && ERR_peek_error() == 0); ++script->calls;
    if (script->errors != 0) { ERR_raise(ERR_LIB_USER, 444); }
    if (script->errors == 2) { ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE); }
    errno = script->native_errno; return script->returned;
}

/** 分类故意改变errno，验证生产核心保存的是原生返回当时原因。 */
static int scripted_error(void *context, SSL *native, int returned)
{
    script_t *script = context; CHECK(native != NULL && returned == script->returned);
    CHECK(script->calls == script->classifications + 1); ++script->classifications;
    errno = ENOTTY; return script->classification;
}

static vireo_tls_handshake_ops_t script_ops(script_t *script)
{
    vireo_tls_handshake_ops_t ops = {script, scripted_policy, scripted_handshake, scripted_error};
    return ops;
}

/** 全部必需地址/回调在任何查询前拒绝，主输出整个字节与旧队列保持。 */
static void arguments_and_table(void)
{
    int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
    script_t script = {.ignored = true}; vireo_tls_handshake_ops_t ops = script_ops(&script);
    vireo_tls_handshake_info_t info; memset(&info, 0xA9, sizeof(info));
    unsigned char original[sizeof(info)]; memcpy(original, &info, sizeof(info));
    ERR_raise(ERR_LIB_USER, 888); unsigned long old = ERR_peek_error();
    vireo_tls_connection_error_t error;
    EXPECT(vireo_tls_connection_handshake_step(NULL, &info, &error), VIREO_RESULT_INVALID_ARGUMENT);
    clean_error(&error);
    EXPECT(vireo_tls_connection_handshake_step(server, NULL, &error), VIREO_RESULT_INVALID_ARGUMENT);
    for (unsigned int i = 0; i < 4; ++i) {
        vireo_tls_handshake_ops_t bad = ops;
        if (i == 1) { bad.sigpipe_ignored = NULL; }
        if (i == 2) { bad.do_handshake = NULL; }
        if (i == 3) { bad.get_error = NULL; }
        EXPECT(vireo_tls_connection_handshake_with_ops(server, &info, &error, i == 0 ? NULL : &bad),
            VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(memcmp(original, &info, sizeof(info)) == 0 && ERR_peek_error() == old);
    }
    CHECK(script.calls == 0 && script.queries == 0 && server->state == VIREO_TLS_HANDSHAKE_INITIAL);
    ERR_clear_error(); release_server(&server, pair);
}

/** 未满足信号政策/查询失败不动TLS状态；修正后仍可尝试正常等待。 */
static void policy_rejection_and_recovery(void)
{
    int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
    script_t script = {.returned = -1, .classification = SSL_ERROR_WANT_READ};
    vireo_tls_handshake_ops_t ops = script_ops(&script);
    vireo_tls_handshake_info_t info; memset(&info, 0xBC, sizeof(info));
    unsigned char original[sizeof(info)]; memcpy(original, &info, sizeof(info));
    vireo_tls_connection_error_t error;
    ERR_raise(ERR_LIB_USER, 999);
    EXPECT(vireo_tls_connection_handshake_with_ops(server, &info, &error, &ops), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(error.stage == VIREO_TLS_CONNECTION_STAGE_SIGNAL_POLICY && error.system_errno == 0);
    CHECK(memcmp(original, &info, sizeof(info)) == 0 && ERR_peek_error() == 0);
    script.query_fails = true;
    EXPECT(vireo_tls_connection_handshake_with_ops(server, &info, &error, &ops), VIREO_RESULT_IO);
    CHECK(error.system_errno == EINTR && script.calls == 0 && script.queries == 2);
    CHECK(memcmp(original, &info, sizeof(info)) == 0 && server->state == VIREO_TLS_HANDSHAKE_INITIAL);
    script.query_fails = false; script.ignored = true;
    EXPECT(vireo_tls_connection_handshake_with_ops(server, &info, &error, &ops), VIREO_OK);
    CHECK(info.state == VIREO_TLS_HANDSHAKE_HANDSHAKING && info.native_called);
    CHECK(script.calls == 1 && script.queries == 3); clean_error(&error);
    release_server(&server, pair);
}

/** 确定性覆盖READ→WRITE→READ，inspect不再把库before误判为从未尝试。 */
static void directions_and_observation(void)
{
    int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
    script_t script = {.returned = -1, .ignored = true};
    vireo_tls_handshake_ops_t ops = script_ops(&script);
    int directions[] = {SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE, SSL_ERROR_WANT_READ};
    for (size_t i = 0; i < 3; ++i) {
        script.classification = directions[i];
        vireo_tls_handshake_info_t info; vireo_tls_connection_error_t error;
        ERR_raise(ERR_LIB_USER, 900);
        EXPECT(vireo_tls_connection_handshake_with_ops(server, &info, &error, &ops), VIREO_OK);
        CHECK(info.native_called && info.state == VIREO_TLS_HANDSHAKE_HANDSHAKING);
        CHECK(info.wait == (i == 1 ? VIREO_TLS_HANDSHAKE_WAIT_WRITE : VIREO_TLS_HANDSHAKE_WAIT_READ));
        CHECK(script.calls == i + 1 && script.classifications == i + 1); clean_error(&error);
        vireo_tls_connection_info_t snapshot;
        EXPECT(vireo_tls_connection_inspect(server, &snapshot, NULL), VIREO_OK);
        CHECK(snapshot.handshake_started && !snapshot.handshake_complete);
        CHECK(snapshot.handshake_state == info.state && snapshot.handshake_wait == info.wait);
        CHECK(SSL_in_before(server->native) == 1 && ERR_peek_error() == 0);
    }
    release_server(&server, pair);
}

/** 错误分类、errno0/EINTR、OOM优先范围及失败后零调用；缓存独立于输出与库队列。 */
static void fatal_classification_and_cache(void)
{
    struct scenario { int returned; int classification; int native_errno; unsigned int errors; vireo_result_t result; };
    struct scenario const scenarios[] = {
        {-1, SSL_ERROR_SYSCALL, EINTR, 0, VIREO_RESULT_IO},
        {-1, SSL_ERROR_SYSCALL, 0, 0, VIREO_RESULT_IO},
        {-1, SSL_ERROR_SYSCALL, EPIPE, 2, VIREO_RESULT_IO},
        {0, SSL_ERROR_ZERO_RETURN, 0, 0, VIREO_RESULT_PROTOCOL},
        {-1, SSL_ERROR_SSL, 0, 1, VIREO_RESULT_PROTOCOL},
        {-1, SSL_ERROR_SSL, 0, 2, VIREO_RESULT_NO_MEMORY},
        {-1, SSL_ERROR_WANT_X509_LOOKUP, 0, 0, VIREO_RESULT_INTERNAL},
        {-1, SSL_ERROR_WANT_ASYNC, 0, 0, VIREO_RESULT_INTERNAL},
        {-1, SSL_ERROR_WANT_CLIENT_HELLO_CB, 0, 0, VIREO_RESULT_INTERNAL},
        {-1, SSL_ERROR_WANT_RETRY_VERIFY, 0, 0, VIREO_RESULT_INTERNAL},
        {-1, SSL_ERROR_NONE, 0, 0, VIREO_RESULT_INTERNAL},
        {1, SSL_ERROR_NONE, 0, 0, VIREO_RESULT_INTERNAL},
        {2, SSL_ERROR_NONE, 0, 0, VIREO_RESULT_INTERNAL}
    };
    for (size_t i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); ++i) {
        struct scenario const *scenario = &scenarios[i];
        int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
        script_t script = {.returned = scenario->returned, .classification = scenario->classification,
            .native_errno = scenario->native_errno, .errors = scenario->errors, .ignored = true};
        vireo_tls_handshake_ops_t ops = script_ops(&script);
        vireo_tls_handshake_info_t info; vireo_tls_connection_error_t error;
        EXPECT(vireo_tls_connection_handshake_with_ops(server, &info, &error, &ops), scenario->result);
        CHECK(info.native_called && info.state == VIREO_TLS_HANDSHAKE_FAILED && info.wait == VIREO_TLS_HANDSHAKE_WAIT_NONE);
        CHECK(error.stage == VIREO_TLS_CONNECTION_STAGE_HANDSHAKE && script.calls == 1 && script.queries == 1);
        CHECK(script.classifications == (scenario->returned <= 0 ? 1U : 0U));
        CHECK(error.system_errno == (scenario->classification == SSL_ERROR_SYSCALL ? scenario->native_errno : 0));
        CHECK(error.has_more_errors == (scenario->errors == 2));
        if (scenario->errors != 0) { CHECK(ERR_GET_REASON((unsigned long)error.openssl_error_code) == 444); }
        else { CHECK(error.openssl_error_code == 0); }
        vireo_tls_connection_error_t first = error;
        ERR_raise(ERR_LIB_USER, 500); memset(&error, 0, sizeof(error));
        EXPECT(vireo_tls_connection_handshake_step(server, &info, &error), scenario->result);
        CHECK(!info.native_called && error.stage == first.stage && error.system_errno == first.system_errno);
        CHECK(error.openssl_error_code == first.openssl_error_code && error.has_more_errors == first.has_more_errors);
        CHECK(script.calls == 1 && script.queries == 1 && ERR_peek_error() == 0);
        vireo_tls_connection_info_t snapshot;
        EXPECT(vireo_tls_connection_inspect(server, &snapshot, NULL), VIREO_OK);
        CHECK(snapshot.handshake_state == VIREO_TLS_HANDSHAKE_FAILED && snapshot.handshake_started);
        release_server(&server, pair);
    }
}

/** 本层无效生命周期在原生前拒绝，两个主输出全部保持；恢复后资源仍配对。 */
static void invalid_lifecycle_preserves_outputs(void)
{
    int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
    for (unsigned int i = 0; i < 7; ++i) {
        if (i == 0) { server->state = (vireo_tls_handshake_state_t)99; }
        if (i == 1) { server->wait = VIREO_TLS_HANDSHAKE_WAIT_READ; }
        if (i == 2) { server->state = VIREO_TLS_HANDSHAKE_ESTABLISHED; }
        if (i == 3) { server->state = VIREO_TLS_HANDSHAKE_HANDSHAKING; }
        if (i == 4) { server->state = VIREO_TLS_HANDSHAKE_FAILED; }
        if (i == 5) { server->failure_result = VIREO_RESULT_IO; }
        if (i == 6) { server->failure_error.has_more_errors = true; }
        vireo_tls_handshake_info_t info; memset(&info, 0xDA, sizeof(info));
        unsigned char saved[sizeof(info)]; memcpy(saved, &info, sizeof(info));
        vireo_tls_connection_error_t error;
        EXPECT(vireo_tls_connection_handshake_step(server, &info, &error), VIREO_RESULT_INTERNAL);
        CHECK(memcmp(saved, &info, sizeof(info)) == 0 && error.stage == VIREO_TLS_CONNECTION_STAGE_INSPECT);
        vireo_tls_connection_info_t snapshot; memset(&snapshot, 0xB3, sizeof(snapshot));
        unsigned char previous[sizeof(snapshot)]; memcpy(previous, &snapshot, sizeof(snapshot));
        EXPECT(vireo_tls_connection_inspect(server, &snapshot, NULL), VIREO_RESULT_INTERNAL);
        CHECK(memcmp(previous, &snapshot, sizeof(snapshot)) == 0);
        server->state = VIREO_TLS_HANDSHAKE_INITIAL; server->wait = VIREO_TLS_HANDSHAKE_WAIT_NONE;
        server->failure_result = VIREO_OK;
        server->failure_error = (vireo_tls_connection_error_t){VIREO_TLS_CONNECTION_STAGE_NONE, 0, 0, false};
    }
    release_server(&server, pair);
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

/** 测试驱动绝对截止，只用于终止坏测试，不当作产品握手期限已接线。 */
static int64_t monotonic_ms(void)
{
    struct timespec now; CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (int64_t)now.tv_sec * INT64_C(1000) + now.tv_nsec / INT64_C(1000000);
}

/** 最新方向映射poll，最多2048轮/5秒；无外网、sleep或无限忙循环。 */
static vireo_result_t drive(peer_fixture_t *fixture)
{
    vireo_tls_handshake_info_t step; vireo_tls_connection_error_t error;
    EXPECT(vireo_tls_connection_handshake_step(fixture->server, &step, &error), VIREO_OK);
    CHECK(step.state == VIREO_TLS_HANDSHAKE_HANDSHAKING && step.wait == VIREO_TLS_HANDSHAKE_WAIT_READ);
    ++fixture->read_waits;
    client_step(fixture);
    int64_t deadline = monotonic_ms() + 5000;
    for (size_t round = 0; round < 2048 && monotonic_ms() < deadline; ++round) {
        if (step.state == VIREO_TLS_HANDSHAKE_ESTABLISHED && fixture->client_done) { return VIREO_OK; }
        struct pollfd fds[2] = {
            {step.state == VIREO_TLS_HANDSHAKE_ESTABLISHED ? -1 : fixture->pair[0],
                step.wait == VIREO_TLS_HANDSHAKE_WAIT_WRITE ? POLLOUT : POLLIN, 0},
            {fixture->client_done || fixture->client_failed ? -1 : fixture->pair[1],
                fixture->client_wait == VIREO_TLS_HANDSHAKE_WAIT_WRITE ? POLLOUT : POLLIN, 0}
        };
        int polled = poll(fds, 2, 50); CHECK(polled >= 0 || errno == EINTR);
        if (polled <= 0) { continue; }
        if (fds[0].revents != 0) {
            errno = ECHILD;
            vireo_result_t result = vireo_tls_connection_handshake_step(fixture->server, &step, &error);
            CHECK(errno == ECHILD && step.native_called);
            if (result != VIREO_OK) { CHECK(step.state == VIREO_TLS_HANDSHAKE_FAILED); return result; }
            clean_error(&error);
            if (step.wait == VIREO_TLS_HANDSHAKE_WAIT_READ) { ++fixture->read_waits; }
            if (step.wait == VIREO_TLS_HANDSHAKE_WAIT_WRITE) { ++fixture->write_waits; }
        }
        if (fds[1].revents != 0) { client_step(fixture); }
    }
    CHECK(false); return VIREO_RESULT_INTERNAL;
}

/** 真正没收到字节时仍可已尝试握手，不能再要求SSL离开before状态。 */
static void real_empty_read_wait(void)
{
    int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
    vireo_tls_handshake_info_t step; vireo_tls_connection_error_t error;
    int flags = fcntl(pair[0], F_GETFL);
    EXPECT(vireo_tls_connection_handshake_step(server, &step, &error), VIREO_OK);
    CHECK(step.native_called && step.wait == VIREO_TLS_HANDSHAKE_WAIT_READ); clean_error(&error);
    vireo_tls_connection_info_t info;
    EXPECT(vireo_tls_connection_inspect(server, &info, NULL), VIREO_OK);
    CHECK(info.handshake_started && !info.handshake_complete && fcntl(pair[0], F_GETFL) == flags);
    release_server(&server, pair);
}

/** 信任和名称验证均成功；原context包装已释放，完成重复step无新握手。 */
static void real_verified_handshake(void)
{
    peer_fixture_t fixture = make_peer(0, true, "vireo-034-test.invalid", false);
    int flags = fcntl(fixture.pair[0], F_GETFL), descriptor = fcntl(fixture.pair[0], F_GETFD);
    CHECK(drive(&fixture) == VIREO_OK && fixture.read_waits > 0);
    CHECK(SSL_get_verify_result(fixture.client) == X509_V_OK && SSL_version(fixture.client) == TLS1_3_VERSION);
    vireo_tls_connection_info_t info;
    EXPECT(vireo_tls_connection_inspect(fixture.server, &info, NULL), VIREO_OK);
    CHECK(info.handshake_started && info.handshake_complete && info.handshake_state == VIREO_TLS_HANDSHAKE_ESTABLISHED);
    vireo_tls_handshake_info_t step;
    EXPECT(vireo_tls_connection_handshake_step(fixture.server, &step, NULL), VIREO_OK);
    CHECK(!step.native_called && step.state == VIREO_TLS_HANDSHAKE_ESTABLISHED);
    CHECK(fcntl(fixture.pair[0], F_GETFL) == flags && fcntl(fixture.pair[0], F_GETFD) == descriptor);
    release_peer(&fixture);
}

/** 真实80KiB级证书链配合小send buffer，完整协商包含写阻塞及续调度。 */
static void real_write_wait_and_resume(void)
{
    peer_fixture_t fixture = make_peer(128, true, "vireo-034-test.invalid", false);
    int bytes = 1024; CHECK(setsockopt(fixture.pair[0], SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes)) == 0);
    CHECK(drive(&fixture) == VIREO_OK && fixture.write_waits > 0);
    (void)printf("real WANT_READ=%zu WANT_WRITE=%zu; trusted TLS1.3 completed\n", fixture.read_waits, fixture.write_waits);
    release_peer(&fixture);
}

/** 明文字节和不相交TLS版本各自通过真实库失败，不从注入推定协议互操作。 */
static void real_protocol_failures(void)
{
    int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
    CHECK(send(pair[1], "plain-text", 10, MSG_NOSIGNAL) == 10);
    vireo_tls_handshake_info_t step; vireo_tls_connection_error_t error;
    EXPECT(vireo_tls_connection_handshake_step(server, &step, &error), VIREO_RESULT_PROTOCOL);
    CHECK(step.state == VIREO_TLS_HANDSHAKE_FAILED && error.openssl_error_code != 0);
    release_server(&server, pair);
    peer_fixture_t fixture = make_peer(0, true, "vireo-034-test.invalid", true);
    CHECK(drive(&fixture) == VIREO_RESULT_PROTOCOL);
    release_peer(&fixture);
}

/** 真实EOF按OpenSSL3分类；真实WANT_WRITE后关peer再步进验证断端不杀进程。 */
static void real_disconnect_and_epipe(void)
{
    int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
    CHECK(close(pair[1]) == 0); pair[1] = -1;
    vireo_tls_handshake_info_t step; vireo_tls_connection_error_t error;
    EXPECT(vireo_tls_connection_handshake_step(server, &step, &error), VIREO_RESULT_PROTOCOL);
    CHECK(error.openssl_error_code != 0 && error.system_errno == 0);
    release_server(&server, pair);
    peer_fixture_t fixture = make_peer(128, true, "vireo-034-test.invalid", false);
    int bytes = 1024; CHECK(setsockopt(fixture.pair[0], SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes)) == 0);
    client_step(&fixture);
    EXPECT(vireo_tls_connection_handshake_step(fixture.server, &step, NULL), VIREO_OK);
    CHECK(step.wait == VIREO_TLS_HANDSHAKE_WAIT_WRITE);
    SSL_free(fixture.client); fixture.client = NULL;
    CHECK(close(fixture.pair[1]) == 0); fixture.pair[1] = -1;
    EXPECT(vireo_tls_connection_handshake_step(fixture.server, &step, &error), VIREO_RESULT_IO);
    CHECK(error.system_errno == EPIPE || error.system_errno == ECONNRESET);
    (void)printf("real closed-write errno=%d; SIGPIPE ignored in exec child only\n", error.system_errno);
    EXPECT(vireo_tls_connection_handshake_step(fixture.server, &step, NULL), VIREO_RESULT_IO);
    CHECK(!step.native_called); release_peer(&fixture);
}

/** 客户端验证不受服务端SSL_VERIFY_NONE影响：错名称和不信任根均拒绝。 */
static void real_client_identity_rejections(void)
{
    peer_fixture_t wrong_name = make_peer(0, true, "wrong.invalid", false);
    CHECK(drive(&wrong_name) == VIREO_RESULT_PROTOCOL && wrong_name.client_failed);
    CHECK(SSL_get_verify_result(wrong_name.client) == X509_V_ERR_HOSTNAME_MISMATCH);
    release_peer(&wrong_name);
    peer_fixture_t untrusted = make_peer(0, false, "vireo-034-test.invalid", false);
    CHECK(drive(&untrusted) == VIREO_RESULT_PROTOCOL && untrusted.client_failed);
    CHECK(SSL_get_verify_result(untrusted.client) != X509_V_OK);
    release_peer(&untrusted);
}

static void empty_handler(int signal_number) { (void)signal_number; }

/** 仅exec后的专属单线程进程设置策略；默认/handler/仅屏蔽都应拒绝且不改pending。 */
static int policy_child(char const *mode)
{
    struct sigaction action = {0}; CHECK(sigemptyset(&action.sa_mask) == 0);
    action.sa_handler = strcmp(mode, "--policy-handler") == 0 ? empty_handler : SIG_DFL;
    CHECK(sigaction(SIGPIPE, &action, NULL) == 0);
    bool blocked = strcmp(mode, "--policy-blocked") == 0;
    sigset_t set; CHECK(sigemptyset(&set) == 0 && sigaddset(&set, SIGPIPE) == 0);
    if (blocked) { CHECK(sigprocmask(SIG_BLOCK, &set, NULL) == 0 && raise(SIGPIPE) == 0); }
    int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
    vireo_tls_handshake_info_t step; memset(&step, 0xAC, sizeof(step));
    unsigned char saved[sizeof(step)]; memcpy(saved, &step, sizeof(step));
    vireo_tls_connection_error_t error;
    EXPECT(vireo_tls_connection_handshake_step(server, &step, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(error.stage == VIREO_TLS_CONNECTION_STAGE_SIGNAL_POLICY && memcmp(saved, &step, sizeof(step)) == 0);
    CHECK(server->state == VIREO_TLS_HANDSHAKE_INITIAL);
    struct sigaction after; CHECK(sigaction(SIGPIPE, NULL, &after) == 0 && after.sa_handler == action.sa_handler);
    sigset_t pending; CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == (blocked ? 1 : 0));
    release_server(&server, pair); (void)printf("policy child %s passed\n", mode); return 0;
}

/** 父进程只fork→exec/_exit，不在两者间初始化OpenSSL或执行工程测试。 */
static void run_exec(char const *mode)
{
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) {
        execl("/proc/self/exe", "vireo_tls_handshake_test", mode, (char *)NULL); _exit(127);
    }
    int status = 0; pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited == -1 && errno == EINTR);
    CHECK(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void real_signal_policy_rejections(void)
{
    run_exec("--policy-default"); run_exec("--policy-handler"); run_exec("--policy-blocked");
}

/** 真实双端六组全部在独立exec进程中设置SIG_IGN，不能改变CTest父进程策略。 */
static int real_child(void)
{
    struct sigaction action = {0}; action.sa_handler = SIG_IGN; CHECK(sigemptyset(&action.sa_mask) == 0);
    CHECK(sigaction(SIGPIPE, &action, NULL) == 0);
    size_t before = fd_count();
#define RUN(function) do { function(); (void)puts("[PASS] " #function); } while (0)
    RUN(real_empty_read_wait);
    RUN(real_verified_handshake);
    RUN(real_write_wait_and_resume);
    RUN(real_protocol_failures);
    RUN(real_disconnect_and_epipe);
    RUN(real_client_identity_rejections);
#undef RUN
    CHECK(fd_count() == before); (void)printf("6 real groups passed; fd %zu -> %zu\n", before, fd_count());
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--real") == 0) { return real_child(); }
    if (argc == 2 && strncmp(argv[1], "--policy-", 9) == 0) { return policy_child(argv[1]); }
    CHECK(argc == 1); size_t before = fd_count();
    struct sigaction initial, after; sigset_t original_mask, final_mask;
    CHECK(sigaction(SIGPIPE, NULL, &initial) == 0 && sigprocmask(SIG_BLOCK, NULL, &original_mask) == 0);
#define RUN(function) do { function(); (void)puts("[PASS] " #function); } while (0)
    RUN(arguments_and_table);
    RUN(policy_rejection_and_recovery);
    RUN(directions_and_observation);
    RUN(fatal_classification_and_cache);
    RUN(invalid_lifecycle_preserves_outputs);
    RUN(real_signal_policy_rejections);
#undef RUN
    run_exec("--real");
    CHECK(sigaction(SIGPIPE, NULL, &after) == 0 && after.sa_handler == initial.sa_handler);
    CHECK(sigprocmask(SIG_BLOCK, NULL, &final_mask) == 0);
    CHECK(sigismember(&original_mask, SIGPIPE) == sigismember(&final_mask, SIGPIPE));
    CHECK(fd_count() == before);
    (void)printf("12 groups passed (6 scripted/policy + 6 real); fd %zu -> %zu; parent SIGPIPE preserved\n", before, fd_count());
    return 0;
}
