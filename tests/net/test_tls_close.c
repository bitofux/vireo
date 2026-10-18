/*
- PROJECT : VIREO
- FILE    : test_tls_close.c
- AUTHOR  : bitofux
- DATE    : 2026-10-17
- BRIEF   : 此模块负责：
- -- 单步TLS关闭、固定期限/稳定重试及真实双向收尾验证
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
    vireo_result_t expect_result = (expression); CHECK(expect_result == (expected)); CHECK(errno == ECHILD); \
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


/** 统一小配置，单元上限4保证低水位3不会在半单元时暂停。 */
static vireo_tls_io_options_t small_options(void)
{
    vireo_tls_io_options_t options = {32, 32, 32832, 4, 3, 24, 8, 24}; return options;
}

/** own模拟只设置本层阶段；不冒充真实握手，真实网络组另行完成双方验证。 */
static vireo_tls_connection_t *script_server(int pair[2])
{
    vireo_tls_connection_t *server = make_server(pair, 0);
    server->state = VIREO_TLS_HANDSHAKE_ESTABLISHED;
    vireo_tls_io_options_t options = small_options();
    EXPECT(vireo_tls_connection_io_configure(server, &options, NULL), VIREO_OK);
    return server;
}

/** 真实握手后才配置；本层容量不受测试消息边界限制。 */
static peer_fixture_t connected(size_t read_capacity, size_t write_capacity)
{
    peer_fixture_t f = make_peer(0, true, "vireo-034-test.invalid", false);
    CHECK(drive(&f) == VIREO_OK && SSL_get_verify_result(f.client) == X509_V_OK);
    CHECK(SSL_version(f.client) == TLS1_3_VERSION);
    vireo_tls_io_options_t options = {read_capacity, write_capacity, read_capacity + write_capacity + 32768,
        1, read_capacity / 4, read_capacity, write_capacity / 4, write_capacity};
    EXPECT(vireo_tls_connection_io_configure(f.server, &options, NULL), VIREO_OK);
    return f;
}

/** 测试客户端一次原生操作紧邻分类；成功确认字节，正常WANT不改变输入offset。 */
static size_t client_io(SSL *client, uint8_t *data, size_t size, bool writing)
{
    ERR_clear_error(); errno = 0; size_t bytes = 0;
    int returned = writing ? SSL_write_ex(client, data, size, &bytes) : SSL_read_ex(client, data, size, &bytes);
    int error = returned == 1 ? SSL_ERROR_NONE : SSL_get_error(client, returned);
    CHECK(returned == 1 || error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE);
    ERR_clear_error(); return returned == 1 ? bytes : 0;
}

typedef struct event {
    char operation;
    int returned, classification, native_errno;
    size_t bytes;
    unsigned int errors;
} event_t;
typedef struct script {
    event_t events[24];
    size_t count, calls, classified, queries;
    int policy_result;
    bool ignored, classify_pending;
    void const *read_pointer, *write_pointer;
    size_t read_length, write_length;
    uint8_t write_bytes[16384];
    bool read_locked, write_locked;
} script_t;

static void push(script_t *s, char op, int returned, int classification, size_t bytes, int native_errno, unsigned int errors)
{ CHECK(s->count < 24); s->events[s->count++] = (event_t){op, returned, classification, native_errno, bytes, errors}; }
static int policy(void *context, bool *ignored)
{
    script_t *s = context; CHECK(!s->classify_pending); ++s->queries;
    errno = EINTR; *ignored = s->ignored; return s->policy_result;
}
static int execute(script_t *s, char op, void const *data, size_t size, size_t *confirmed)
{
    CHECK(!s->classify_pending && s->calls < s->count && errno == 0 && ERR_peek_error() == 0);
    event_t event = s->events[s->calls++]; CHECK(event.operation == op);
    if (op == 'r') {
        if (s->read_locked) { CHECK(data == s->read_pointer && size == s->read_length); }
        s->read_pointer = data; s->read_length = size;
        s->read_locked = event.returned == 0 && (event.classification == SSL_ERROR_WANT_READ || event.classification == SSL_ERROR_WANT_WRITE);
    } else if (op == 'w') {
        if (s->write_locked) {
            CHECK(data == s->write_pointer && size == s->write_length && memcmp(data, s->write_bytes, size) == 0);
        }
        s->write_pointer = data; s->write_length = size; memcpy(s->write_bytes, data, size);
        s->write_locked = event.returned == 0 && (event.classification == SSL_ERROR_WANT_READ || event.classification == SSL_ERROR_WANT_WRITE);
    }
    if (confirmed != NULL) { *confirmed = event.bytes == SIZE_MAX ? size : event.bytes; }
    if (event.errors != 0) { ERR_raise(ERR_LIB_USER, 718); }
    if (event.errors == 2) { ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE); }
    s->classify_pending = op == 's' ? event.returned < 0 : event.returned != 1;
    errno = event.native_errno;
    return event.returned;
}
static int scripted_read(void *context, SSL *ssl, void *data, size_t size, size_t *confirmed)
{
    CHECK(ssl != NULL); int returned = execute(context, 'r', data, size, confirmed);
    if (returned == 1 && *confirmed <= size) { memset(data, 0x41, *confirmed); }
    return returned;
}
static int scripted_write(void *context, SSL *ssl, void const *data, size_t size, size_t *confirmed)
{ CHECK(ssl != NULL); return execute(context, 'w', data, size, confirmed); }
static int scripted_shutdown(void *context, SSL *ssl)
{ CHECK(ssl != NULL); return execute(context, 's', NULL, 0, NULL); }
static int classification(void *context, SSL *ssl, int returned)
{
    script_t *s = context; event_t event = s->events[s->calls - 1];
    CHECK(ssl != NULL && s->classify_pending && returned == event.returned && errno == event.native_errno);
    s->classify_pending = false; ++s->classified; errno = ENOTTY; return event.classification;
}
static vireo_tls_close_ops_t script_ops(script_t *s)
{
    vireo_tls_close_ops_t ops = {{s, policy, scripted_read, scripted_write, classification}, scripted_shutdown};
    return ops;
}
static vireo_result_t step(vireo_tls_connection_t *server, script_t *s, uint64_t now, size_t budget,
    vireo_tls_close_progress_t *progress, vireo_tls_connection_error_t *error)
{
    vireo_tls_close_ops_t ops = script_ops(s);
    return vireo_tls_connection_close_with_ops(server, now, budget, progress, error, &ops);
}
static vireo_tls_close_info_t close_info(vireo_tls_connection_t *server)
{
    vireo_tls_close_info_t info;
    EXPECT(vireo_tls_connection_close_inspect(server, &info, NULL), VIREO_OK); return info;
}
static vireo_tls_io_info_t io_info(vireo_tls_connection_t *server)
{
    vireo_tls_io_info_t info;
    EXPECT(vireo_tls_connection_io_inspect(server, &info, NULL), VIREO_OK); return info;
}

/** 基本参数、完整own表、模式/正预算拒绝保持整个输出及旧错误队列。 */
static void arguments_and_modes(void)
{
    int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
    vireo_tls_close_progress_t progress; memset(&progress, 0xA7, sizeof(progress));
    uint8_t saved[sizeof(progress)]; memcpy(saved, &progress, sizeof(saved));
    script_t s = {.ignored = true}; vireo_tls_close_ops_t ops = script_ops(&s);
    CHECK(close_info(server).state == VIREO_TLS_CLOSE_NONE);
    EXPECT(vireo_tls_connection_close_request(server, 1, 2, NULL), VIREO_RESULT_BUSY);
    EXPECT(step(server, &s, 1, 16, &progress, NULL), VIREO_RESULT_BUSY);
    ERR_raise(ERR_LIB_USER, 719); unsigned long old = ERR_peek_error();
    EXPECT(vireo_tls_connection_close_request(NULL, 1, 2, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tls_connection_close_inspect(NULL, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tls_connection_close_inspect(server, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(step(NULL, &s, 1, 16, &progress, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(step(server, &s, 1, 16, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(step(server, &s, 1, 0, &progress, NULL), VIREO_RESULT_RANGE);
    for (unsigned int i = 0; i < 7; ++i) {
        vireo_tls_close_ops_t bad = ops;
        if (i == 1) { bad.io.sigpipe_ignored = NULL; } if (i == 2) { bad.io.read_ex = NULL; }
        if (i == 3) { bad.io.write_ex = NULL; } if (i == 4) { bad.io.get_error = NULL; }
        if (i == 5) { bad.shutdown = NULL; }
        EXPECT(vireo_tls_connection_close_with_ops(server, 1, 0, &progress, NULL, i == 0 ? NULL : &bad),
            i == 6 ? VIREO_RESULT_RANGE : VIREO_RESULT_INVALID_ARGUMENT);
    }
    CHECK(ERR_peek_error() == old && memcmp(saved, &progress, sizeof(saved)) == 0 && s.queries == 0);
    ERR_clear_error();
    server->state = VIREO_TLS_HANDSHAKE_ESTABLISHED;
    SSL_set_quiet_shutdown(server->native, 1);
    vireo_tls_io_options_t options = small_options();
    EXPECT(vireo_tls_connection_io_configure(server, &options, NULL), VIREO_OK);
    CHECK(SSL_get_quiet_shutdown(server->native) == 0);
    release_server(&server, pair);
}

/** 发起后新入队/普通收发/flow门禁不改输出或水位；固定期限不能延长。 */
static void request_and_gates(void)
{
    int pair[2]; vireo_tls_connection_t *server = script_server(pair);
    EXPECT(vireo_tls_connection_enqueue(server, (uint8_t const *)"abc", 3, NULL), VIREO_OK);
    EXPECT(vireo_tls_connection_close_request(server, 10, 20, NULL), VIREO_OK);
    vireo_tls_close_info_t info = close_info(server);
    CHECK(info.state == VIREO_TLS_CLOSE_DRAINING && info.deadline_ns == 20 && info.last_now_ns == 10);
    CHECK(info.operation == VIREO_TLS_IO_OPERATION_WRITE && info.resume && !info.local_notify_sent);
    EXPECT(vireo_tls_connection_close_request(server, 11, 30, NULL), VIREO_RESULT_BUSY);
    EXPECT(vireo_tls_connection_enqueue(server, NULL, 0, NULL), VIREO_RESULT_BUSY);
    vireo_tls_io_budget_t budget = {1, 1}; vireo_tls_io_progress_t progress;
    memset(&progress, 0xA7, sizeof(progress)); uint8_t saved[sizeof(progress)]; memcpy(saved, &progress, sizeof(saved));
    EXPECT(vireo_tls_connection_send(server, &budget, &progress, NULL), VIREO_RESULT_BUSY);
    EXPECT(vireo_tls_connection_receive(server, &budget, &progress, NULL), VIREO_RESULT_BUSY);
    CHECK(memcmp(saved, &progress, sizeof(saved)) == 0 && io_info(server).write_size == 3);
    vireo_tls_io_flow_t flow; memset(&flow, 0xA7, sizeof(flow));
    uint8_t flow_saved[sizeof(flow)]; memcpy(flow_saved, &flow, sizeof(flow));
    EXPECT(vireo_tls_connection_flow_refresh(server, &flow, NULL), VIREO_RESULT_BUSY);
    CHECK(memcmp(flow_saved, &flow, sizeof(flow)) == 0 && !server->io.write_pressure);
    CHECK(close_info(server).deadline_ns == 20); release_server(&server, pair);
}

/** 原read WANT_WRITE先续同参数；转READ后立刻可排空/notify，原read暂存留待收尾。 */
static void retry_order_and_tail(void)
{
    int pair[2]; vireo_tls_connection_t *server = script_server(pair); script_t s = {.ignored = true};
    vireo_tls_close_ops_t ops = script_ops(&s); vireo_tls_io_budget_t budget = {8, 1};
    vireo_tls_io_progress_t moved; vireo_tls_close_progress_t progress;
    push(&s, 'r', 0, SSL_ERROR_WANT_WRITE, 0, 0, 0);
    EXPECT(vireo_tls_connection_io_with_ops(server, &budget, &moved, NULL, false, &ops.io), VIREO_OK);
    EXPECT(vireo_tls_connection_enqueue(server, (uint8_t const *)"abc", 3, NULL), VIREO_OK);
    EXPECT(vireo_tls_connection_close_request(server, 1, 100, NULL), VIREO_OK);
    CHECK(close_info(server).operation == VIREO_TLS_IO_OPERATION_READ);
    push(&s, 'r', 0, SSL_ERROR_WANT_READ, 0, 0, 0);
    EXPECT(step(server, &s, 2, 8, &progress, NULL), VIREO_OK);
    CHECK(progress.info.operation == VIREO_TLS_IO_OPERATION_WRITE && progress.info.resume);
    push(&s, 'w', 1, 0, SIZE_MAX, 0, 0);
    EXPECT(step(server, &s, 3, 8, &progress, NULL), VIREO_OK); CHECK(progress.write_bytes == 3);
    push(&s, 's', 0, 0, 0, 0, 0);
    EXPECT(step(server, &s, 4, 1, &progress, NULL), VIREO_OK); /* stale read长度8不阻止notify预算1 */
    CHECK(progress.info.local_notify_sent && progress.info.state == VIREO_TLS_CLOSE_WAIT_PEER);
    push(&s, 'r', 1, 0, 5, 0, 0);
    EXPECT(step(server, &s, 5, 8, &progress, NULL), VIREO_OK); CHECK(progress.read_bytes == 5);
    push(&s, 'r', 0, SSL_ERROR_ZERO_RETURN, 0, 0, 0);
    EXPECT(step(server, &s, 6, 8, &progress, NULL), VIREO_OK);
    CHECK(progress.info.state == VIREO_TLS_CLOSE_COMPLETE && progress.info.peer_notify_received && io_info(server).read_size == 5);
    EXPECT(step(server, &s, UINT64_MAX, 1, &progress, NULL), VIREO_OK); CHECK(!progress.native_called);
    CHECK(s.calls == 6 && s.classified == 3 && !s.classify_pending); release_server(&server, pair);
}

/** 入场前write WANT快照必须先原参数完成；新预算不足、回退均无原生/信号查询。 */
static void write_retry_budget_and_deadline(void)
{
    int pair[2]; vireo_tls_connection_t *server = script_server(pair); script_t s = {.ignored = true};
    vireo_tls_close_ops_t ops = script_ops(&s); vireo_tls_io_budget_t budget = {8, 1}; vireo_tls_io_progress_t moved;
    EXPECT(vireo_tls_connection_enqueue(server, (uint8_t const *)"abcdefghijk", 11, NULL), VIREO_OK);
    push(&s, 'w', 0, SSL_ERROR_WANT_WRITE, 0, 0, 0);
    EXPECT(vireo_tls_connection_io_with_ops(server, &budget, &moved, NULL, true, &ops.io), VIREO_OK);
    EXPECT(vireo_tls_connection_close_request(server, 10, 20, NULL), VIREO_OK);
    vireo_tls_close_progress_t progress; memset(&progress, 0xA7, sizeof(progress));
    uint8_t saved[sizeof(progress)]; memcpy(saved, &progress, sizeof(saved));
    EXPECT(step(server, &s, 9, 8, &progress, NULL), VIREO_RESULT_RANGE);
    EXPECT(step(server, &s, 11, 7, &progress, NULL), VIREO_RESULT_RANGE);
    CHECK(memcmp(saved, &progress, sizeof(saved)) == 0 && s.queries == 1 && close_info(server).last_now_ns == 10);
    push(&s, 'w', 1, 0, SIZE_MAX, 0, 0);
    EXPECT(step(server, &s, 11, 8, &progress, NULL), VIREO_OK);
    CHECK(progress.write_bytes == 8 && io_info(server).write_size == 3 && s.calls == 2);
    vireo_tls_connection_error_t error;
    EXPECT(step(server, &s, 20, 1, &progress, &error), VIREO_RESULT_TIMEOUT);
    CHECK(!progress.native_called && error.stage == VIREO_TLS_CONNECTION_STAGE_CLOSE_DEADLINE);
    CHECK(error.system_errno == 0 && error.openssl_error_code == 0 && s.queries == 2 && io_info(server).write_size == 3);
    EXPECT(step(server, &s, 0, 1, &progress, NULL), VIREO_RESULT_TIMEOUT);
    EXPECT(vireo_tls_connection_enqueue(server, NULL, 0, NULL), VIREO_RESULT_TIMEOUT);
    EXPECT(vireo_tls_connection_send(server, &budget, &moved, NULL), VIREO_RESULT_TIMEOUT);
    EXPECT(vireo_tls_connection_receive(server, &budget, &moved, NULL), VIREO_RESULT_TIMEOUT);
    CHECK(s.calls == 2); release_server(&server, pair);
}

/** shutdown 0/1不get_error，负数WANT重试不以SENT位伪装成功；原生前信号拒绝不推进。 */
static void notify_wants_and_signal(void)
{
    int pair[2]; vireo_tls_connection_t *server = script_server(pair); script_t s = {0};
    EXPECT(vireo_tls_connection_close_request(server, 1, 100, NULL), VIREO_OK);
    vireo_tls_close_progress_t progress; memset(&progress, 0xA7, sizeof(progress));
    uint8_t saved[sizeof(progress)]; memcpy(saved, &progress, sizeof(saved));
    vireo_tls_connection_error_t error;
    for (int policy_case = 0; policy_case < 3; ++policy_case) {
        s.policy_result = policy_case == 1 ? -1 : (policy_case == 2 ? 3 : 0);
        EXPECT(step(server, &s, 2, 16, &progress, &error), policy_case == 1 ? VIREO_RESULT_IO :
            (policy_case == 2 ? VIREO_RESULT_INTERNAL : VIREO_RESULT_INVALID_ARGUMENT));
        CHECK(memcmp(saved, &progress, sizeof(saved)) == 0 && close_info(server).last_now_ns == 1 && s.calls == 0);
    }
    s.policy_result = 0; s.ignored = true;
    push(&s, 's', -1, SSL_ERROR_WANT_WRITE, 0, 0, 0);
    EXPECT(step(server, &s, 2, 16, &progress, NULL), VIREO_OK);
    SSL_set_shutdown(server->native, SSL_SENT_SHUTDOWN); /* own仅证明本层不信单独SENT位 */
    CHECK(!close_info(server).local_notify_sent && progress.info.wait == VIREO_TLS_IO_WAIT_WRITE && !progress.info.resume);
    push(&s, 's', -1, SSL_ERROR_WANT_READ, 0, 0, 0);
    EXPECT(step(server, &s, 3, 16, &progress, NULL), VIREO_OK);
    CHECK(progress.info.operation == VIREO_TLS_IO_OPERATION_SHUTDOWN && progress.info.wait == VIREO_TLS_IO_WAIT_READ);
    push(&s, 's', 0, 0, 0, 0, 0);
    EXPECT(step(server, &s, 4, 16, &progress, &error), VIREO_OK); clean_error(&error);
    CHECK(s.classified == 2 && progress.info.local_notify_sent && progress.info.resume);
    push(&s, 'r', 0, SSL_ERROR_ZERO_RETURN, 0, 0, 0);
    EXPECT(step(server, &s, 5, 16, &progress, NULL), VIREO_OK);
    CHECK(progress.info.state == VIREO_TLS_CLOSE_COMPLETE && !progress.info.resume);
    release_server(&server, pair);
    server = script_server(pair); s = (script_t){.ignored = true};
    server->io.read_eof = true;
    EXPECT(vireo_tls_connection_close_request(server, 0, UINT64_MAX, NULL), VIREO_OK);
    push(&s, 's', 1, 0, 0, 0, 0);
    EXPECT(step(server, &s, 0, 1, &progress, NULL), VIREO_OK);
    CHECK(progress.info.state == VIREO_TLS_CLOSE_COMPLETE && s.classified == 0);
    release_server(&server, pair);
}

/** 关闭读绕过旧压力，仍受真实容量/locked长度约束；consume后无需fd边沿可继续。 */
static void capacity_and_pressure(void)
{
    int pair[2]; vireo_tls_connection_t *server = script_server(pair); script_t s = {.ignored = true};
    server->io.read_pressure = true; server->io.write_pressure = true;
    EXPECT(vireo_tls_connection_close_request(server, 1, 100, NULL), VIREO_OK);
    vireo_tls_close_progress_t progress;
    push(&s, 's', 0, 0, 0, 0, 0); EXPECT(step(server, &s, 2, 32, &progress, NULL), VIREO_OK);
    push(&s, 'r', 1, 0, SIZE_MAX, 0, 0); EXPECT(step(server, &s, 3, 32, &progress, NULL), VIREO_OK);
    CHECK(progress.read_bytes == 32 && progress.info.needs_consume && !progress.info.resume);
    EXPECT(step(server, &s, 4, 32, &progress, NULL), VIREO_OK);
    CHECK(!progress.native_called && progress.stop_reason == VIREO_TLS_CLOSE_STOP_NEED_CONSUME && s.calls == 2);
    uint8_t const *view; size_t size;
    EXPECT(vireo_tls_connection_read_peek(server, &view, &size, NULL), VIREO_OK); CHECK(size == 32 && view[31] == 0x41);
    EXPECT(vireo_tls_connection_read_consume(server, 32, NULL), VIREO_OK); CHECK(close_info(server).resume);
    s.ignored = false; uint64_t last = close_info(server).last_now_ns;
    EXPECT(step(server, &s, 5, 32, &progress, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(close_info(server).last_now_ns == last && server->io.read_retry_bytes == 0);
    s.ignored = true; push(&s, 'r', 0, SSL_ERROR_ZERO_RETURN, 0, 0, 0);
    EXPECT(step(server, &s, 5, 32, &progress, NULL), VIREO_OK);
    CHECK(progress.info.state == VIREO_TLS_CLOSE_COMPLETE); release_server(&server, pair);
}

/** 超时可发生首次原生前/notify WANT后/等待消费时；不查询信号、不触任何原生。 */
static void timeout_boundaries(void)
{
    for (unsigned int mode = 0; mode < 3; ++mode) {
        int pair[2]; vireo_tls_connection_t *server = script_server(pair); script_t s = {.ignored = true};
        vireo_tls_close_progress_t progress;
        EXPECT(vireo_tls_connection_close_request(server, 0, mode == 0 ? 0 : UINT64_MAX, NULL), VIREO_OK);
        if (mode != 0) {
            push(&s, 's', mode == 1 ? -1 : 0, SSL_ERROR_WANT_WRITE, 0, 0, 0);
            EXPECT(step(server, &s, 0, 32, &progress, NULL), VIREO_OK);
            if (mode == 2) {
                push(&s, 'r', 1, 0, SIZE_MAX, 0, 0); EXPECT(step(server, &s, 1, 32, &progress, NULL), VIREO_OK);
            }
        }
        size_t queries = s.queries, calls = s.calls;
        EXPECT(step(server, &s, mode == 0 ? 0 : UINT64_MAX, 1, &progress, NULL), VIREO_RESULT_TIMEOUT);
        CHECK(!progress.native_called && !progress.info.resume && progress.info.operation == VIREO_TLS_IO_OPERATION_NONE);
        CHECK(s.queries == queries && s.calls == calls);
        EXPECT(step(server, &s, 0, 1, &progress, NULL), VIREO_RESULT_TIMEOUT); release_server(&server, pair);
    }
}

/** 原生首错表覆盖I/O与shutdown，诊断不受分类回调errno覆盖；不在fatal后shutdown。 */
static void fatal_tables(void)
{
    for (unsigned int mode = 0; mode < 9; ++mode) {
        int pair[2]; vireo_tls_connection_t *server = script_server(pair); script_t s = {.ignored = true};
        char op = mode == 7 ? 'w' : (mode == 8 ? 'r' : 's');
        if (op == 'w') { EXPECT(vireo_tls_connection_enqueue(server, (uint8_t const *)"abc", 3, NULL), VIREO_OK); }
        EXPECT(vireo_tls_connection_close_request(server, 1, 10, NULL), VIREO_OK);
        vireo_tls_close_progress_t progress; vireo_tls_connection_error_t error;
        if (op == 'r') { push(&s, 's', 0, 0, 0, 0, 0); EXPECT(step(server, &s, 2, 32, &progress, NULL), VIREO_OK); }
        int category = mode == 0 ? SSL_ERROR_SYSCALL : (mode == 1 || mode == 2 || mode >= 7 ? SSL_ERROR_SSL :
            (mode == 3 ? SSL_ERROR_ZERO_RETURN : SSL_ERROR_WANT_X509_LOOKUP));
        vireo_result_t expected = mode == 0 ? VIREO_RESULT_IO : (mode == 2 ? VIREO_RESULT_NO_MEMORY :
            (mode == 1 || mode == 3 || mode >= 7 ? VIREO_RESULT_PROTOCOL : VIREO_RESULT_INTERNAL));
        push(&s, op, mode == 5 ? 2 : (mode == 6 ? -2 : (op == 's' ? -1 : 0)), category, 0, EPIPE, mode == 2 ? 2U : 1U);
        EXPECT(step(server, &s, 3, 32, &progress, &error), expected);
        CHECK(progress.native_called && progress.info.state == VIREO_TLS_CLOSE_FAILED && error.openssl_error_code != 0);
        CHECK(error.system_errno == (mode == 0 ? EPIPE : 0));
        vireo_tls_connection_error_t first = error; size_t calls = s.calls;
        EXPECT(step(server, &s, UINT64_MAX, 32, &progress, &error), expected);
        CHECK(!progress.native_called && error.stage == first.stage && error.openssl_error_code == first.openssl_error_code && s.calls == calls);
        EXPECT(vireo_tls_connection_enqueue(server, NULL, 0, &error), expected);
        if (op != 's') { CHECK(io_info(server).state == VIREO_TLS_IO_FAILED); }
        release_server(&server, pair);
    }
    int pair[2]; vireo_tls_connection_t *server = script_server(pair); script_t s = {.ignored = true};
    vireo_tls_close_ops_t ops = script_ops(&s); vireo_tls_io_budget_t budget = {32, 1}; vireo_tls_io_progress_t moved;
    push(&s, 'r', 0, SSL_ERROR_SSL, 0, 0, 1);
    EXPECT(vireo_tls_connection_io_with_ops(server, &budget, &moved, NULL, false, &ops.io), VIREO_RESULT_PROTOCOL);
    EXPECT(vireo_tls_connection_close_request(server, 1, 10, NULL), VIREO_RESULT_PROTOCOL);
    CHECK(close_info(server).state == VIREO_TLS_CLOSE_NONE && s.calls == 1); release_server(&server, pair);
}

/** 真实调用始终使用base clock；绝对期限由公开受检运算产生。 */
static vireo_monotonic_ns_t now_ns(void)
{
    vireo_monotonic_ns_t now = 0; EXPECT(vireo_clock_monotonic_now(&now, NULL), VIREO_OK); return now;
}
static void request(peer_fixture_t *f, uint64_t duration)
{
    vireo_monotonic_ns_t now = now_ns(), due = 0;
    EXPECT(vireo_clock_deadline_after(now, duration, &due), VIREO_OK);
    EXPECT(vireo_tls_connection_close_request(f->server, now, due, NULL), VIREO_OK);
}
static vireo_tls_close_progress_t real_step(peer_fixture_t *f)
{
    vireo_tls_close_progress_t progress;
    EXPECT(vireo_tls_connection_close_step_at(f->server, now_ns(), 16384, &progress, NULL), VIREO_OK);
    CHECK(progress.read_bytes <= 16384 && progress.write_bytes <= 16384 && !(progress.read_bytes && progress.write_bytes));
    return progress;
}
static int client_notify(SSL *client)
{
    ERR_clear_error(); errno = 0; int returned = SSL_shutdown(client);
    int classification = returned < 0 ? SSL_get_error(client, returned) : SSL_ERROR_NONE;
    CHECK(returned >= 0 || classification == SSL_ERROR_WANT_READ || classification == SSL_ERROR_WANT_WRITE);
    ERR_clear_error(); return returned;
}
static void historical(peer_fixture_t *f)
{
    vireo_tls_connection_info_t info; vireo_tls_handshake_info_t handshake;
    EXPECT(vireo_tls_connection_inspect(f->server, &info, NULL), VIREO_OK); CHECK(info.handshake_complete);
    EXPECT(vireo_tls_connection_handshake_step(f->server, &handshake, NULL), VIREO_OK);
    CHECK(!handshake.native_called && handshake.state == VIREO_TLS_HANDSHAKE_ESTABLISHED);
}

/** 已有read WANT_READ不阻止主动notify；对端收到后仍能发尾部，COMPLETE保留明文。 */
static void real_active_tail(void)
{
    peer_fixture_t f = connected(64, 64);
    vireo_tls_io_budget_t budget = {64, 1}; vireo_tls_io_progress_t read;
    EXPECT(vireo_tls_connection_receive(f.server, &budget, &read, NULL), VIREO_OK);
    CHECK(read.wait == VIREO_TLS_IO_WAIT_READ);
    request(&f, UINT64_C(5000000000)); vireo_tls_close_progress_t progress = real_step(&f);
    CHECK(progress.native_called && progress.info.local_notify_sent && progress.info.state == VIREO_TLS_CLOSE_WAIT_PEER);
    uint8_t byte; size_t size = 0; ERR_clear_error();
    int returned = SSL_read_ex(f.client, &byte, 1, &size);
    int category = returned == 1 ? SSL_ERROR_NONE : SSL_get_error(f.client, returned);
    CHECK(returned == 0 && category == SSL_ERROR_ZERO_RETURN); ERR_clear_error();
    uint8_t tail[5] = {'a', 0, 'b', 'c', 'd'}; CHECK(client_io(f.client, tail, sizeof(tail), true) == sizeof(tail));
    CHECK(client_notify(f.client) == 1);
    progress = real_step(&f); CHECK(progress.read_bytes == sizeof(tail));
    progress = real_step(&f); CHECK(progress.info.state == VIREO_TLS_CLOSE_COMPLETE && progress.info.peer_notify_received);
    uint8_t const *view;
    EXPECT(vireo_tls_connection_read_peek(f.server, &view, &size, NULL), VIREO_OK);
    CHECK(size == sizeof(tail) && memcmp(view, tail, size) == 0);
    historical(&f); progress = real_step(&f); CHECK(!progress.native_called);
    EXPECT(vireo_tls_connection_read_consume(f.server, size, NULL), VIREO_OK); release_peer(&f);
}

/** 被动先EOF仍可排空最终响应；双方先request/notify也完成双向收尾。 */
static void real_passive_and_simultaneous(void)
{
    for (unsigned int mode = 0; mode < 2; ++mode) {
        peer_fixture_t f = connected(64, 64); CHECK(client_notify(f.client) == 0);
        if (mode == 0) {
            vireo_tls_io_budget_t budget = {64, 2}; vireo_tls_io_progress_t read;
            EXPECT(vireo_tls_connection_receive(f.server, &budget, &read, NULL), VIREO_OK); CHECK(io_info(f.server).read_eof);
            EXPECT(vireo_tls_connection_enqueue(f.server, (uint8_t const *)"reply", 5, NULL), VIREO_OK);
        }
        request(&f, UINT64_C(5000000000));
        if (mode == 0) {
            vireo_tls_close_progress_t moved = real_step(&f); CHECK(moved.write_bytes == 5 && !moved.info.local_notify_sent);
            uint8_t response[5]; CHECK(client_io(f.client, response, 5, false) == 5 && memcmp(response, "reply", 5) == 0);
        }
        vireo_tls_close_progress_t progress = real_step(&f);
        if (progress.info.state != VIREO_TLS_CLOSE_COMPLETE) { progress = real_step(&f); }
        CHECK(progress.info.state == VIREO_TLS_CLOSE_COMPLETE && client_notify(f.client) == 1);
        historical(&f); release_peer(&f);
    }
}

/** 实际read FIFO满不吞尾部或close_notify；消费后不依赖新fd事件即可继续。 */
static void real_full_buffer(void)
{
    peer_fixture_t f = connected(8, 64); request(&f, UINT64_C(5000000000));
    CHECK(real_step(&f).info.local_notify_sent);
    uint8_t source[16]; for (size_t i = 0; i < sizeof(source); ++i) { source[i] = (uint8_t)i; }
    CHECK(client_io(f.client, source, sizeof(source), true) == sizeof(source)); CHECK(client_notify(f.client) == 0);
    vireo_tls_close_progress_t progress = real_step(&f); CHECK(progress.read_bytes == 8 && progress.info.needs_consume);
    progress = real_step(&f); CHECK(!progress.native_called && progress.stop_reason == VIREO_TLS_CLOSE_STOP_NEED_CONSUME);
    uint8_t actual[16]; size_t received = 0;
    for (size_t round = 0; round < 8 && close_info(f.server).state != VIREO_TLS_CLOSE_COMPLETE; ++round) {
        uint8_t const *view; size_t size;
        EXPECT(vireo_tls_connection_read_peek(f.server, &view, &size, NULL), VIREO_OK);
        CHECK(size <= sizeof(actual) - received); memcpy(actual + received, view, size); received += size;
        EXPECT(vireo_tls_connection_read_consume(f.server, size, NULL), VIREO_OK); (void)real_step(&f);
    }
    CHECK(close_info(f.server).state == VIREO_TLS_CLOSE_COMPLETE && received == 16 && memcmp(actual, source, 16) == 0);
    CHECK(client_notify(f.client) == 1); historical(&f); release_peer(&f);
}

/** 真实write WANT在request前发生，关闭必须原快照恢复并精确排空后才notify。 */
static void real_write_drain(void)
{
    peer_fixture_t f = connected(64, 100000); uint8_t source[80000], actual[80000];
    for (size_t i = 0; i < sizeof(source); ++i) { source[i] = (uint8_t)(i * 17); }
    EXPECT(vireo_tls_connection_enqueue(f.server, source, sizeof(source), NULL), VIREO_OK);
    int limit = 1024; CHECK(setsockopt(f.pair[0], SOL_SOCKET, SO_SNDBUF, &limit, sizeof(limit)) == 0);
    vireo_tls_io_budget_t budget = {16384, 1}; vireo_tls_io_progress_t moved;
    EXPECT(vireo_tls_connection_send(f.server, &budget, &moved, NULL), VIREO_OK);
    CHECK(moved.wait == VIREO_TLS_IO_WAIT_WRITE && io_info(f.server).write_retry_bytes == 16384);
    request(&f, UINT64_C(5000000000)); size_t received = 0, wants = 0; int64_t deadline = monotonic_ms() + 5000;
    for (size_t round = 0; round < 10000 && received < sizeof(source) && monotonic_ms() < deadline; ++round) {
        received += client_io(f.client, actual + received, sizeof(source) - received, false);
        vireo_tls_close_progress_t progress = real_step(&f);
        if (progress.stop_reason == VIREO_TLS_CLOSE_STOP_WANT) { ++wants; }
        if (io_info(f.server).write_size != 0) { CHECK(!progress.info.local_notify_sent); }
    }
    CHECK(received == sizeof(source) && memcmp(source, actual, sizeof(source)) == 0 && io_info(f.server).write_size == 0 && wants > 0);
    if (!close_info(f.server).local_notify_sent) { CHECK(real_step(&f).info.local_notify_sent); }
    CHECK(client_notify(f.client) == 0);
    CHECK(real_step(&f).info.state == VIREO_TLS_CLOSE_COMPLETE); CHECK(client_notify(f.client) == 1);
    (void)printf("write drain: %zu exact bytes, %zu close WANTs\n", received, wants); release_peer(&f);
}

/** 裁剪poll上限后即使没有fd新事件，也用新采样时间触发真实WANT_READ后的超时。 */
static void real_silent_timeout(void)
{
    peer_fixture_t f = connected(64, 64); request(&f, UINT64_C(30000000)); CHECK(real_step(&f).info.local_notify_sent);
    vireo_tls_close_progress_t progress = real_step(&f); CHECK(progress.info.wait == VIREO_TLS_IO_WAIT_READ && !progress.info.resume);
    for (size_t round = 0; round < 20 && now_ns() < progress.info.deadline_ns; ++round) {
        vireo_monotonic_ns_t now = now_ns(); int milliseconds = 0;
        EXPECT(vireo_clock_deadline_wait_ms(now, progress.info.deadline_ns, 100, &milliseconds), VIREO_OK);
        struct pollfd fd = {f.pair[0], POLLIN, 0}; CHECK(poll(&fd, 1, milliseconds) == 0);
    }
    CHECK(now_ns() >= progress.info.deadline_ns);
    EXPECT(vireo_tls_connection_close_step_at(f.server, now_ns(), 16384, &progress, NULL), VIREO_RESULT_TIMEOUT);
    CHECK(!progress.native_called && progress.info.state == VIREO_TLS_CLOSE_FAILED);
    historical(&f); release_peer(&f);
}

/** 关闭中的裸EOF和EPIPE保留真实首错；晚到期限/普通收发/历史握手不复活网络。 */
static void real_disconnects(void)
{
    for (unsigned int mode = 0; mode < 2; ++mode) {
        peer_fixture_t f = connected(64, 64); request(&f, UINT64_C(5000000000));
        if (mode == 0) {
            CHECK(real_step(&f).info.local_notify_sent);
            uint8_t byte; size_t size = 0; ERR_clear_error();
            int returned = SSL_read_ex(f.client, &byte, 1, &size);
            int category = returned == 1 ? SSL_ERROR_NONE : SSL_get_error(f.client, returned);
            CHECK(returned == 0 && category == SSL_ERROR_ZERO_RETURN); ERR_clear_error();
        }
        SSL_free(f.client); f.client = NULL; CHECK(close(f.pair[1]) == 0); f.pair[1] = -1;
        vireo_tls_close_progress_t progress; vireo_tls_connection_error_t error;
        vireo_result_t expected = mode == 0 ? VIREO_RESULT_PROTOCOL : VIREO_RESULT_IO;
        EXPECT(vireo_tls_connection_close_step_at(f.server, now_ns(), 16384, &progress, &error), expected);
        CHECK(progress.native_called && !progress.info.peer_notify_received);
        if (mode == 0) { CHECK(error.openssl_error_code != 0); }
        else { CHECK(error.system_errno == EPIPE || error.system_errno == ECONNRESET); }
        EXPECT(vireo_tls_connection_close_step_at(f.server, UINT64_MAX, 16384, &progress, NULL), expected);
        CHECK(!progress.native_called); historical(&f); release_peer(&f);
    }
}

/** 默认handler且SIGPIPE已blocked/pending：首次前到期不需要信号策略，也不消费pending。 */
static void real_pre_native_timeout(void)
{
    struct sigaction action = {0}; action.sa_handler = SIG_DFL; CHECK(sigemptyset(&action.sa_mask) == 0);
    CHECK(sigaction(SIGPIPE, &action, NULL) == 0);
    sigset_t mask; CHECK(sigemptyset(&mask) == 0 && sigaddset(&mask, SIGPIPE) == 0);
    CHECK(sigprocmask(SIG_BLOCK, &mask, NULL) == 0 && raise(SIGPIPE) == 0);
    int pair[2]; vireo_tls_connection_t *server = script_server(pair); /* own established，不执行网络握手 */
    EXPECT(vireo_tls_connection_close_request(server, 10, 10, NULL), VIREO_OK);
    vireo_tls_close_progress_t progress;
    EXPECT(vireo_tls_connection_close_step_at(server, 10, 1, &progress, NULL), VIREO_RESULT_TIMEOUT);
    CHECK(!progress.native_called); sigset_t pending;
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 1);
    CHECK(sigaction(SIGPIPE, NULL, &action) == 0 && action.sa_handler == SIG_DFL); release_server(&server, pair);
}

static void run_exec(char const *mode)
{
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) { execl("/proc/self/exe", "vireo_tls_close_test", mode, (char *)NULL); _exit(127); }
    int status = 0; pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited == -1 && errno == EINTR);
    CHECK(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--pre-timeout") == 0) { real_pre_native_timeout(); return 0; }
    if (argc == 2 && strcmp(argv[1], "--real") == 0) {
        struct sigaction action = {0}; action.sa_handler = SIG_IGN; CHECK(sigemptyset(&action.sa_mask) == 0);
        CHECK(sigaction(SIGPIPE, &action, NULL) == 0); size_t before = fd_count();
#define RUN(function) do { function(); (void)puts("[PASS] " #function); } while (0)
        RUN(real_active_tail); RUN(real_passive_and_simultaneous); RUN(real_full_buffer);
        RUN(real_write_drain); RUN(real_silent_timeout); RUN(real_disconnects);
#undef RUN
        CHECK(fd_count() == before); (void)printf("6 real groups passed; fd %zu -> %zu\n", before, fd_count()); return 0;
    }
    CHECK(argc == 1); size_t before = fd_count();
    struct sigaction initial, after; sigset_t mask, after_mask, pending, after_pending;
    CHECK(sigaction(SIGPIPE, NULL, &initial) == 0 && sigprocmask(SIG_BLOCK, NULL, &mask) == 0 && sigpending(&pending) == 0);
#define RUN(function) do { function(); (void)puts("[PASS] " #function); } while (0)
    RUN(arguments_and_modes); RUN(request_and_gates); RUN(retry_order_and_tail); RUN(write_retry_budget_and_deadline);
    RUN(notify_wants_and_signal); RUN(capacity_and_pressure); RUN(timeout_boundaries); RUN(fatal_tables);
#undef RUN
    run_exec("--real"); run_exec("--pre-timeout");
    CHECK(sigaction(SIGPIPE, NULL, &after) == 0 && initial.sa_handler == after.sa_handler);
    CHECK(sigprocmask(SIG_BLOCK, NULL, &after_mask) == 0 && sigpending(&after_pending) == 0);
    CHECK(sigismember(&mask, SIGPIPE) == sigismember(&after_mask, SIGPIPE));
    CHECK(sigismember(&pending, SIGPIPE) == sigismember(&after_pending, SIGPIPE));
    CHECK(fd_count() == before);
    (void)printf("15 groups passed (8 own + 6 real + 1 pre-native process); fd %zu -> %zu; parent SIGPIPE preserved\n", before, fd_count()); return 0;
}

