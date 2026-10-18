/*
- PROJECT : VIREO
- FILE    : test_tls_io.c
- AUTHOR  : bitofux
- DATE    : 2026-10-17
- BRIEF   : 此模块负责：
- -- 固定应用缓冲、own故障、真实双端字节与重试/EOF/flow验证
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

typedef struct item {
    int returned, classification, native_errno;
    size_t confirmed; /**< SIZE_MAX使用请求长度；其余可制造不可能返回。 */
    unsigned int errors; /**< 1普通原因，2附OOM。 */
} item_t;
typedef struct script {
    item_t items[16];
    size_t count, calls, classifications, queries;
    size_t reject_query; /**< 1起查询编号，0不拒绝。 */
    bool query_error;
    void const *snapshot;
    size_t length;
    uint8_t bytes[16384];
    bool check_snapshot;
} script_t;

static int policy(void *context, bool *out)
{
    script_t *s = context; ++s->queries;
    if (s->queries == s->reject_query) {
        if (s->query_error) { errno = EINTR; return -1; }
        *out = false; return 0;
    }
    *out = true; return 0;
}
static int native(script_t *s, void const *pointer, size_t length, size_t *confirmed, bool writing)
{
    CHECK(errno == 0 && ERR_peek_error() == 0 && s->calls < s->count);
    if (s->check_snapshot) {
        CHECK(pointer == s->snapshot && length == s->length);
        if (writing) { CHECK(memcmp(pointer, s->bytes, length) == 0); }
    }
    s->snapshot = pointer; s->length = length;
    if (writing) { memcpy(s->bytes, pointer, length); }
    item_t item = s->items[s->calls++];
    if (item.errors != 0) { ERR_raise(ERR_LIB_USER, 441); }
    if (item.errors == 2) { ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE); }
    *confirmed = item.confirmed == SIZE_MAX ? length : item.confirmed;
    errno = item.native_errno;
    return item.returned;
}
static int scripted_read(void *context, SSL *ssl, void *data, size_t length, size_t *confirmed)
{
    script_t *s = context; CHECK(ssl != NULL);
    int result = native(s, data, length, confirmed, false);
    if (result == 1 && *confirmed <= length) { memset(data, 0x41, *confirmed); }
    return result;
}
static int scripted_write(void *context, SSL *ssl, void const *data, size_t length, size_t *confirmed)
{ CHECK(ssl != NULL); return native(context, data, length, confirmed, true); }
static int classification(void *context, SSL *ssl, int returned)
{
    script_t *s = context; CHECK(ssl != NULL && returned == s->items[s->calls - 1].returned);
    ++s->classifications; errno = ENOTTY; return s->items[s->calls - 1].classification;
}
static vireo_tls_io_ops_t script_ops(script_t *s)
{ vireo_tls_io_ops_t ops = {s, policy, scripted_read, scripted_write, classification}; return ops; }
static void push(script_t *s, int returned, int error, size_t confirmed, int system_error, unsigned int errors)
{ CHECK(s->count < 16); s->items[s->count++] = (item_t){returned, error, system_error, confirmed, errors}; }
static vireo_result_t step(vireo_tls_connection_t *server, script_t *s, bool writing,
    size_t bytes, size_t calls, vireo_tls_io_progress_t *progress, vireo_tls_connection_error_t *error)
{
    vireo_tls_io_ops_t ops = script_ops(s); vireo_tls_io_budget_t budget = {bytes, calls};
    return vireo_tls_connection_io_with_ops(server, &budget, progress, error, writing, &ops);
}
static vireo_tls_io_info_t info(vireo_tls_connection_t *server)
{
    vireo_tls_io_info_t result;
    EXPECT(vireo_tls_connection_io_inspect(server, &result, NULL), VIREO_OK); return result;
}
static vireo_tls_io_flow_t flow(vireo_tls_connection_t *server)
{
    vireo_tls_io_flow_t result;
    EXPECT(vireo_tls_connection_flow_refresh(server, &result, NULL), VIREO_OK); return result;
}

/** 参数拒绝保持整个输出、旧队列；配置数字先checked加法，无隐式握手/热配。 */
static void configuration_and_arguments(void)
{
    int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
    vireo_tls_io_options_t options = small_options();
    CHECK(info(server).state == VIREO_TLS_IO_DISABLED && !flow(server).want_read);
    vireo_tls_io_progress_t progress; memset(&progress, 0xA9, sizeof(progress));
    unsigned char saved[sizeof(progress)]; memcpy(saved, &progress, sizeof(saved));
    vireo_tls_io_budget_t budget = {4, 1};
    EXPECT(vireo_tls_connection_receive(server, &budget, &progress, NULL), VIREO_RESULT_BUSY);
    EXPECT(vireo_tls_connection_io_configure(server, &options, NULL), VIREO_RESULT_BUSY);
    CHECK(memcmp(saved, &progress, sizeof(saved)) == 0);
    server->state = VIREO_TLS_HANDSHAKE_ESTABLISHED;
    for (unsigned int i = 0; i < 9; ++i) {
        vireo_tls_io_options_t bad = options; vireo_result_t expected = VIREO_RESULT_RANGE;
        if (i == 0) { bad.read_capacity = SIZE_MAX; expected = VIREO_RESULT_OVERFLOW; }
        if (i == 1) { bad.read_low = 2; }
        if (i == 2) { bad.read_high = 33; }
        if (i == 3) { bad.max_buffer_bytes = 32831; }
        if (i == 4) { bad.max_read_unit_bytes = 33; }
        if (i == 5) { bad.write_high = 8; }
        if (i == 6) { bad.max_buffer_bytes = 67108865; }
        if (i == 7) { bad.read_capacity = 0; }
        if (i == 8) { bad.max_read_unit_bytes = 0; }
        ERR_raise(ERR_LIB_USER, 888); unsigned long old = ERR_peek_error();
        EXPECT(vireo_tls_connection_io_configure(server, &bad, NULL), expected);
        CHECK(ERR_peek_error() == old && server->io.state == VIREO_TLS_IO_DISABLED); ERR_clear_error();
    }
    (void)SSL_set_mode(server->native, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    (void)SSL_set_options(server->native, SSL_OP_IGNORE_UNEXPECTED_EOF); SSL_set_read_ahead(server->native, 1);
    EXPECT(vireo_tls_connection_io_configure(server, &options, NULL), VIREO_OK);
    EXPECT(vireo_tls_connection_io_configure(server, &options, NULL), VIREO_RESULT_BUSY);
    CHECK(info(server).buffer_bytes == 32832);
    CHECK((SSL_get_mode(server->native) & SSL_MODE_AUTO_RETRY) != 0);
    CHECK((SSL_get_mode(server->native) & (SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER)) == 0);
    CHECK(SSL_get_read_ahead(server->native) == 0 && (SSL_get_options(server->native) & SSL_OP_IGNORE_UNEXPECTED_EOF) == 0);
    ERR_raise(ERR_LIB_USER, 889); unsigned long old = ERR_peek_error();
    EXPECT(vireo_tls_connection_receive(NULL, &budget, &progress, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tls_connection_send(server, NULL, &progress, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tls_connection_receive(server, &budget, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    budget.max_bytes = 0;
    EXPECT(vireo_tls_connection_receive(server, &budget, &progress, NULL), VIREO_RESULT_RANGE);
    budget.max_bytes = 1; budget.max_native_calls = 0;
    EXPECT(vireo_tls_connection_send(server, &budget, &progress, NULL), VIREO_RESULT_RANGE);
    CHECK(ERR_peek_error() == old && memcmp(saved, &progress, sizeof(saved)) == 0);
    EXPECT(vireo_tls_connection_enqueue(server, NULL, 1, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    uint8_t const *view = (uint8_t const *)&budget; size_t size = 777;
    EXPECT(vireo_tls_connection_read_peek(server, NULL, &size, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tls_connection_read_peek(server, &view, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(view == (uint8_t const *)&budget && size == 777);
    ERR_clear_error();
    EXPECT(vireo_tls_connection_read_peek(server, &view, &size, NULL), VIREO_OK); CHECK(view == NULL && size == 0);
    EXPECT(vireo_tls_connection_enqueue(server, NULL, 0, NULL), VIREO_OK);
    EXPECT(vireo_tls_connection_enqueue(server, (uint8_t const *)"x", 1, NULL), VIREO_OK);
    EXPECT(vireo_tls_connection_enqueue(server, (uint8_t const *)"x", SIZE_MAX, NULL), VIREO_RESULT_OVERFLOW);
    EXPECT(vireo_tls_connection_enqueue(server, (uint8_t const *)"x", 32, NULL), VIREO_RESULT_RANGE);
    EXPECT(vireo_tls_connection_read_consume(server, 1, NULL), VIREO_RESULT_RANGE);
    CHECK(info(server).write_size == 1);
    release_server(&server, pair);
}

typedef struct resources { size_t calls, fail_at, live; } resources_t;
static void *resource_allocate(void *context, size_t size)
{
    resources_t *r = context; if (++r->calls == r->fail_at) { return NULL; }
    void *p = malloc(size); CHECK(p != NULL); ++r->live; return p;
}
static void resource_free(void *context, void *p)
{ resources_t *r = context; CHECK(p != NULL && r->live > 0); --r->live; free(p); }
static vireo_result_t resource_buffer(void *context, size_t size, vireo_buffer_t **out)
{
    resources_t *r = context; if (++r->calls == r->fail_at) { return VIREO_RESULT_NO_MEMORY; }
    vireo_result_t result = vireo_buffer_create(size, out); CHECK(result == VIREO_OK); ++r->live; return result;
}
static void resource_buffer_free(void *context, vireo_buffer_t **out)
{ resources_t *r = context; CHECK(*out != NULL && r->live > 0); --r->live; CHECK(vireo_buffer_destroy(out) == VIREO_OK); }
static bool resource_prepare(void *context, SSL *ssl)
{ resources_t *r = context; CHECK(ssl != NULL); return ++r->calls != r->fail_at; }

/** 所有四资源与晚期prepare逐级失败，配对回收且可重新配置；完整表缺项零调用。 */
static void resource_rollback(void)
{
    for (size_t failure = 1; failure <= 6; ++failure) {
        int pair[2]; vireo_tls_connection_t *server = make_server(pair, 0);
        server->state = VIREO_TLS_HANDSHAKE_ESTABLISHED;
        resources_t resources = {.fail_at = failure};
        vireo_tls_io_config_ops_t ops = {&resources, resource_allocate, resource_free, resource_buffer,
            resource_buffer_free, resource_prepare};
        vireo_tls_io_options_t options = small_options(); vireo_tls_connection_error_t error;
        if (failure == 1) {
            for (unsigned int i = 0; i < 6; ++i) {
                vireo_tls_io_config_ops_t bad = ops;
                if (i == 1) { bad.allocate = NULL; } if (i == 2) { bad.deallocate = NULL; }
                if (i == 3) { bad.buffer_create = NULL; } if (i == 4) { bad.buffer_destroy = NULL; }
                if (i == 5) { bad.prepare = NULL; }
                EXPECT(vireo_tls_connection_io_configure_with_ops(server, &options, NULL, i == 0 ? NULL : &bad),
                    VIREO_RESULT_INVALID_ARGUMENT);
            }
            CHECK(resources.calls == 0);
        }
        vireo_result_t expected = failure <= 4 ? VIREO_RESULT_NO_MEMORY :
            (failure == 5 ? VIREO_RESULT_INTERNAL : VIREO_OK);
        EXPECT(vireo_tls_connection_io_configure_with_ops(server, &options, &error, &ops), expected);
        if (failure <= 5) {
            CHECK(error.stage == VIREO_TLS_CONNECTION_STAGE_CONFIGURE_IO && resources.live == 0);
            CHECK(info(server).state == VIREO_TLS_IO_DISABLED);
            EXPECT(vireo_tls_connection_io_configure(server, &options, NULL), VIREO_OK);
        } else { CHECK(resources.live == 4); }
        release_server(&server, pair); CHECK(resources.live == 0);
    }
}

/** WANT快照不受enqueue/compact影响，预算过小不调用；无确认不消费，精确成功后推进。 */
static void write_snapshot_and_budgets(void)
{
    int pair[2]; vireo_tls_connection_t *server = script_server(pair);
    uint8_t data[40]; for (size_t i = 0; i < sizeof(data); ++i) { data[i] = (uint8_t)i; }
    EXPECT(vireo_tls_connection_enqueue(server, data, 24, NULL), VIREO_OK);
    script_t s = {0}; vireo_tls_io_progress_t progress;
    push(&s, 1, 0, SIZE_MAX, 0, 0);
    EXPECT(step(server, &s, true, 8, 1, &progress, NULL), VIREO_OK);
    CHECK(progress.bytes == 8 && progress.native_calls == 1 && progress.stop_reason == VIREO_TLS_IO_STOP_BYTE_BUDGET);
    push(&s, 0, SSL_ERROR_WANT_WRITE, 0, 0, 0);
    EXPECT(step(server, &s, true, 8, 1, &progress, NULL), VIREO_OK);
    CHECK(progress.bytes == 0 && info(server).write_retry_bytes == 8 && info(server).write_size == 16);
    s.check_snapshot = true;
    EXPECT(vireo_tls_connection_enqueue(server, data + 24, 16, NULL), VIREO_OK);
    vireo_tls_io_progress_t saved = progress;
    ERR_raise(ERR_LIB_USER, 888); unsigned long old = ERR_peek_error();
    EXPECT(step(server, &s, true, 7, 1, &progress, NULL), VIREO_RESULT_RANGE);
    CHECK(memcmp(&saved, &progress, sizeof(saved)) == 0 && ERR_peek_error() == old && s.calls == 2);
    ERR_clear_error(); push(&s, 1, 0, SIZE_MAX, 0, 0);
    EXPECT(step(server, &s, true, 8, 1, &progress, NULL), VIREO_OK);
    CHECK(progress.bytes == 8 && memcmp(s.bytes, data + 8, 8) == 0 && info(server).write_size == 24);
    s.check_snapshot = false; push(&s, 1, 0, SIZE_MAX, 0, 0);
    EXPECT(step(server, &s, true, 32, 1, &progress, NULL), VIREO_OK);
    CHECK(progress.bytes == 24 && progress.stop_reason == VIREO_TLS_IO_STOP_BUFFER_EMPTY);
    release_server(&server, pair);
}

/** 水位等号/中间迟滞、read单元约束、pending原操作优先与交叉方向。 */
static void directions_pressure_and_duplex(void)
{
    int pair[2]; vireo_tls_connection_t *server = script_server(pair);
    script_t s = {0}; vireo_tls_io_progress_t progress;
    push(&s, 0, SSL_ERROR_WANT_READ, 0, 0, 0);
    EXPECT(step(server, &s, false, 8, 1, &progress, NULL), VIREO_OK);
    CHECK(info(server).read_retry_bytes == 8 && !flow(server).resume_read);
    uint8_t data[32] = {0}; EXPECT(vireo_tls_connection_enqueue(server, data, 24, NULL), VIREO_OK);
    CHECK(flow(server).write_pressure);
    push(&s, 0, SSL_ERROR_WANT_READ, 0, 0, 0);
    EXPECT(step(server, &s, true, 8, 1, &progress, NULL), VIREO_OK);
    CHECK(info(server).read_retry_bytes == 8 && info(server).write_retry_bytes == 8);
    vireo_tls_io_flow_t f = flow(server);
    CHECK(f.priority_retry == VIREO_TLS_IO_OPERATION_WRITE && f.want_read && !f.want_write && !f.application_read_enabled);
    EXPECT(step(server, &s, false, 8, 1, &progress, NULL), VIREO_OK);
    CHECK(progress.stop_reason == VIREO_TLS_IO_STOP_RETRY_OTHER && progress.native_calls == 0);
    push(&s, 1, 0, SIZE_MAX, 0, 0);
    EXPECT(step(server, &s, true, 8, 1, &progress, NULL), VIREO_OK);
    CHECK(flow(server).write_pressure); /* 16在8..24中间，锁保持，排空仍允许。 */
    push(&s, 1, 0, SIZE_MAX, 0, 0);
    EXPECT(step(server, &s, true, 8, 1, &progress, NULL), VIREO_OK);
    CHECK(!flow(server).write_pressure); /* 等于low解锁。 */
    push(&s, 1, 0, SIZE_MAX, 0, 0);
    EXPECT(step(server, &s, true, 8, 1, &progress, NULL), VIREO_OK);
    CHECK(info(server).write_size == 0);
    push(&s, 0, SSL_ERROR_WANT_WRITE, 0, 0, 0);
    EXPECT(step(server, &s, false, 8, 1, &progress, NULL), VIREO_OK);
    f = flow(server); CHECK(f.priority_retry == VIREO_TLS_IO_OPERATION_READ && f.want_write && !f.want_read);
    EXPECT(step(server, &s, true, 8, 1, &progress, NULL), VIREO_OK);
    CHECK(progress.stop_reason == VIREO_TLS_IO_STOP_RETRY_OTHER && progress.native_calls == 0);
    push(&s, 1, 0, SIZE_MAX, 0, 0);
    EXPECT(step(server, &s, false, 8, 1, &progress, NULL), VIREO_OK);
    CHECK(progress.bytes == 8 && flow(server).resume_read);
    push(&s, 1, 0, SIZE_MAX, 0, 0);
    EXPECT(step(server, &s, false, 16, 1, &progress, NULL), VIREO_OK);
    CHECK(flow(server).read_pressure && !flow(server).application_read_enabled);
    EXPECT(vireo_tls_connection_read_consume(server, 8, NULL), VIREO_OK); CHECK(flow(server).read_pressure);
    EXPECT(vireo_tls_connection_read_consume(server, 13, NULL), VIREO_OK); CHECK(!flow(server).read_pressure);
    /* read成功后留头洞，再append触发公开compact；view内容与写侧操作独立。 */
    push(&s, 1, 0, SIZE_MAX, 0, 0);
    EXPECT(step(server, &s, false, 16, 1, &progress, NULL), VIREO_OK);
    uint8_t const *view; size_t size;
    EXPECT(vireo_tls_connection_read_peek(server, &view, &size, NULL), VIREO_OK);
    CHECK(size == 19); for (size_t i = 0; i < size; ++i) { CHECK(view[i] == 0x41); }
    EXPECT(vireo_tls_connection_enqueue(server, NULL, 0, NULL), VIREO_OK); (void)flow(server); (void)info(server);
    CHECK(view[0] == 0x41 && view[18] == 0x41);
    release_server(&server, pair);
}

/** 原生错误范围、即时errno、明确OOM、首错缓存以及fatal前已确认明文保留。 */
static void fatal_and_prefix(void)
{
    int errors[] = {SSL_ERROR_SYSCALL, SSL_ERROR_SYSCALL, SSL_ERROR_SSL, SSL_ERROR_SSL,
        SSL_ERROR_WANT_X509_LOOKUP, SSL_ERROR_ZERO_RETURN, SSL_ERROR_NONE, SSL_ERROR_NONE};
    vireo_result_t expected[] = {VIREO_RESULT_IO, VIREO_RESULT_IO, VIREO_RESULT_PROTOCOL, VIREO_RESULT_NO_MEMORY,
        VIREO_RESULT_INTERNAL, VIREO_RESULT_PROTOCOL, VIREO_RESULT_INTERNAL, VIREO_RESULT_INTERNAL};
    for (size_t i = 0; i < 8; ++i) {
        int pair[2]; vireo_tls_connection_t *server = script_server(pair);
        script_t s = {0}; vireo_tls_io_progress_t progress; vireo_tls_connection_error_t error;
        uint8_t bytes[8] = {0}; EXPECT(vireo_tls_connection_enqueue(server, bytes, 8, NULL), VIREO_OK);
        push(&s, i >= 6 ? 1 : 0, errors[i], i == 6 ? 0 : (i == 7 ? 2 : 0), i == 1 ? EINTR : 0,
            i <= 3 ? (i == 0 || i == 3 ? 2U : 1U) : 0U);
        EXPECT(step(server, &s, true, 8, 1, &progress, &error), expected[i]);
        CHECK(info(server).state == VIREO_TLS_IO_FAILED && progress.native_calls == 1 && progress.bytes == 0);
        CHECK(error.stage == VIREO_TLS_CONNECTION_STAGE_SEND && error.system_errno == (i == 1 ? EINTR : 0));
        if (i == 0 || i == 3) { CHECK(error.has_more_errors && error.openssl_error_code != 0); }
        vireo_tls_connection_error_t saved = error;
        EXPECT(step(server, &s, false, 8, 1, &progress, &error), expected[i]);
        CHECK(progress.native_calls == 0 && progress.stop_reason == VIREO_TLS_IO_STOP_ERROR && s.queries == 1);
        CHECK(saved.stage == error.stage && saved.system_errno == error.system_errno &&
            saved.openssl_error_code == error.openssl_error_code && saved.has_more_errors == error.has_more_errors);
        EXPECT(vireo_tls_connection_enqueue(server, NULL, 0, &error), expected[i]);
        CHECK(!flow(server).want_read && !flow(server).want_write);
        CHECK(server->state == VIREO_TLS_HANDSHAKE_ESTABLISHED && server->failure_result == VIREO_OK);
        release_server(&server, pair);
    }
    int pair[2]; vireo_tls_connection_t *server = script_server(pair);
    script_t s = {0}; vireo_tls_io_progress_t progress;
    push(&s, 1, 0, 4, 0, 0); push(&s, 0, SSL_ERROR_SSL, 0, 0, 1);
    EXPECT(step(server, &s, false, 16, 2, &progress, NULL), VIREO_RESULT_PROTOCOL);
    CHECK(progress.bytes == 4 && progress.native_calls == 2 && info(server).read_size == 4);
    uint8_t const *view; size_t size;
    EXPECT(vireo_tls_connection_read_peek(server, &view, &size, NULL), VIREO_OK); CHECK(size == 4 && view[3] == 0x41);
    EXPECT(vireo_tls_connection_read_consume(server, 4, NULL), VIREO_OK);
    release_server(&server, pair);
    server = make_server(pair, 0); server->state = VIREO_TLS_HANDSHAKE_ESTABLISHED;
    vireo_tls_io_options_t options = {32, 32768, 65568, 1, 0, 32, 0, 32768};
    EXPECT(vireo_tls_connection_io_configure(server, &options, NULL), VIREO_OK);
    uint8_t *payload = calloc(20000, 1); CHECK(payload != NULL);
    EXPECT(vireo_tls_connection_enqueue(server, payload, 20000, NULL), VIREO_OK); free(payload);
    s = (script_t){0}; push(&s, 1, 0, SIZE_MAX, 0, 0); push(&s, 0, SSL_ERROR_SYSCALL, 0, EPIPE, 1);
    EXPECT(step(server, &s, true, 32768, 2, &progress, NULL), VIREO_RESULT_IO);
    CHECK(progress.bytes == 16384 && progress.native_calls == 2 && info(server).write_size == 3616);
    release_server(&server, pair);
}

/** 原生前信号拒绝保持报告；第二次查询失败仍提交之前确认前缀，不缓存应用fatal。 */
static void signal_and_output_boundaries(void)
{
    int pair[2]; vireo_tls_connection_t *server = script_server(pair);
    script_t s = {.reject_query = 1}; vireo_tls_io_progress_t progress;
    memset(&progress, 0xAB, sizeof(progress)); unsigned char saved[sizeof(progress)]; memcpy(saved, &progress, sizeof(saved));
    EXPECT(step(server, &s, false, 16, 2, &progress, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(saved, &progress, sizeof(saved)) == 0 && info(server).read_retry_bytes == 0);
    s.reject_query = 3; s.query_error = true; push(&s, 1, 0, 4, 0, 0);
    vireo_tls_connection_error_t error;
    EXPECT(step(server, &s, false, 16, 2, &progress, &error), VIREO_RESULT_IO);
    CHECK(progress.bytes == 4 && progress.native_calls == 1 && error.system_errno == EINTR && info(server).state == VIREO_TLS_IO_OPEN);
    s.reject_query = 0; push(&s, 0, SSL_ERROR_WANT_READ, 0, 0, 0);
    EXPECT(step(server, &s, false, 16, 2, &progress, NULL), VIREO_OK);
    CHECK(progress.native_calls == 1 && progress.wait == VIREO_TLS_IO_WAIT_READ && !flow(server).resume_read);
    release_server(&server, pair);
}

/** 满区/迟滞暂停、call预算、读重试预算、正常EOF与完整own表/输出保护。 */
static void capacity_eof_and_tables(void)
{
    int pair[2]; vireo_tls_connection_t *server = script_server(pair);
    script_t s = {0}; vireo_tls_io_progress_t progress;
    vireo_tls_io_ops_t ops = script_ops(&s); vireo_tls_io_budget_t budget = {32, 1};
    memset(&progress, 0xBC, sizeof(progress)); unsigned char saved[sizeof(progress)]; memcpy(saved, &progress, sizeof(saved));
    for (unsigned int i = 0; i < 5; ++i) {
        vireo_tls_io_ops_t bad = ops;
        if (i == 1) { bad.sigpipe_ignored = NULL; } if (i == 2) { bad.read_ex = NULL; }
        if (i == 3) { bad.write_ex = NULL; } if (i == 4) { bad.get_error = NULL; }
        EXPECT(vireo_tls_connection_io_with_ops(server, &budget, &progress, NULL, false, i == 0 ? NULL : &bad),
            VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(memcmp(saved, &progress, sizeof(saved)) == 0 && s.queries == 0);
    }
    push(&s, 1, 0, 24, 0, 0);
    EXPECT(step(server, &s, false, 32, 1, &progress, NULL), VIREO_OK);
    CHECK(progress.stop_reason == VIREO_TLS_IO_STOP_CALL_BUDGET && progress.bytes == 24);
    CHECK(flow(server).read_pressure);
    EXPECT(step(server, &s, false, 32, 1, &progress, NULL), VIREO_OK);
    CHECK(progress.stop_reason == VIREO_TLS_IO_STOP_FLOW_PAUSED && progress.native_calls == 0);
    EXPECT(vireo_tls_connection_read_consume(server, 21, NULL), VIREO_OK); CHECK(!flow(server).read_pressure);
    push(&s, 1, 0, SIZE_MAX, 0, 0);
    EXPECT(step(server, &s, false, 32, 1, &progress, NULL), VIREO_OK);
    CHECK(progress.bytes == 29 && progress.stop_reason == VIREO_TLS_IO_STOP_BUFFER_FULL);
    EXPECT(step(server, &s, false, 32, 1, &progress, NULL), VIREO_OK); CHECK(progress.native_calls == 0);
    EXPECT(vireo_tls_connection_read_consume(server, 32, NULL), VIREO_OK); (void)flow(server);
    push(&s, 0, SSL_ERROR_WANT_READ, 0, 0, 0);
    EXPECT(step(server, &s, false, 8, 1, &progress, NULL), VIREO_OK);
    memcpy(saved, &progress, sizeof(saved)); size_t calls = s.calls;
    EXPECT(step(server, &s, false, 7, 1, &progress, NULL), VIREO_RESULT_RANGE);
    CHECK(s.calls == calls && memcmp(saved, &progress, sizeof(saved)) == 0);
    s.check_snapshot = true; push(&s, 1, 0, 4, 0, 0);
    EXPECT(step(server, &s, false, 8, 1, &progress, NULL), VIREO_OK);
    s.check_snapshot = false; push(&s, 0, SSL_ERROR_ZERO_RETURN, 0, 0, 0);
    EXPECT(step(server, &s, false, 8, 1, &progress, NULL), VIREO_OK);
    CHECK(progress.stop_reason == VIREO_TLS_IO_STOP_PEER_EOF && info(server).read_size == 4);
    EXPECT(step(server, &s, false, 8, 1, &progress, NULL), VIREO_OK); CHECK(progress.native_calls == 0);
    release_server(&server, pair);
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

/** 双向跨记录、NUL、预算/多调用精确比较，接收逐轮consume复用固定区。 */
static void real_bidirectional_bytes(void)
{
    peer_fixture_t f = connected(32768, 131072);
    int flags = fcntl(f.pair[0], F_GETFL), descriptor = fcntl(f.pair[0], F_GETFD);
    size_t total = 70003;
    uint8_t *source = malloc(total), *actual = malloc(total); CHECK(source != NULL && actual != NULL);
    for (size_t i = 0; i < total; ++i) { source[i] = (uint8_t)(i * 37); }
    EXPECT(vireo_tls_connection_enqueue(f.server, source, 30000, NULL), VIREO_OK);
    EXPECT(vireo_tls_connection_enqueue(f.server, source + 30000, total - 30000, NULL), VIREO_OK);
    vireo_tls_io_budget_t budget = {17000, 2}; size_t received = 0;
    int64_t deadline = monotonic_ms() + 5000;
    for (size_t round = 0; round < 10000 && received < total && monotonic_ms() < deadline; ++round) {
        vireo_tls_io_progress_t progress;
        EXPECT(vireo_tls_connection_send(f.server, &budget, &progress, NULL), VIREO_OK);
        CHECK(progress.bytes <= 17000 && progress.native_calls <= 2);
        received += client_io(f.client, actual + received, total - received, false);
    }
    CHECK(received == total && memcmp(source, actual, total) == 0 && info(f.server).write_size == 0);
    size_t submitted = 0; received = 0; deadline = monotonic_ms() + 5000;
    for (size_t round = 0; round < 10000 && received < total && monotonic_ms() < deadline; ++round) {
        if (submitted < total) {
            size_t length = total - submitted < 8192 ? total - submitted : 8192;
            submitted += client_io(f.client, source + submitted, length, true);
        }
        vireo_tls_io_progress_t progress;
        EXPECT(vireo_tls_connection_receive(f.server, &budget, &progress, NULL), VIREO_OK);
        CHECK(progress.bytes <= 17000 && progress.native_calls <= 2);
        uint8_t const *view; size_t size;
        EXPECT(vireo_tls_connection_read_peek(f.server, &view, &size, NULL), VIREO_OK);
        CHECK(size <= total - received); if (size != 0) { memcpy(actual + received, view, size); }
        received += size; EXPECT(vireo_tls_connection_read_consume(f.server, size, NULL), VIREO_OK);
    }
    CHECK(submitted == total && received == total && memcmp(source, actual, total) == 0);
    CHECK(fcntl(f.pair[0], F_GETFL) == flags && fcntl(f.pair[0], F_GETFD) == descriptor);
    free(actual); free(source); release_peer(&f);
}

/** 真实应用write阻塞，原快照跨FIFO整理及追加保持，再排空得到精确原序列。 */
static void real_application_want_write(void)
{
    peer_fixture_t f = connected(32768, 100000);
    size_t total = 108000;
    uint8_t *source = malloc(total), *actual = malloc(total); CHECK(source != NULL && actual != NULL);
    for (size_t i = 0; i < total; ++i) { source[i] = (uint8_t)(i * 17 + 3); }
    EXPECT(vireo_tls_connection_enqueue(f.server, source, 70000, NULL), VIREO_OK);
    vireo_tls_io_budget_t first = {8000, 1}, budget = {32768, 4}; vireo_tls_io_progress_t progress;
    EXPECT(vireo_tls_connection_send(f.server, &first, &progress, NULL), VIREO_OK); CHECK(progress.bytes == 8000);
    int bytes = 1024; CHECK(setsockopt(f.pair[0], SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes)) == 0);
    EXPECT(vireo_tls_connection_send(f.server, &budget, &progress, NULL), VIREO_OK);
    CHECK(progress.stop_reason == VIREO_TLS_IO_STOP_WOULD_BLOCK && progress.wait == VIREO_TLS_IO_WAIT_WRITE);
    CHECK(info(f.server).write_retry_bytes == 16384 && progress.bytes == 0);
    uint8_t snapshot[16384]; memcpy(snapshot, f.server->io.write_scratch, sizeof(snapshot));
    EXPECT(vireo_tls_connection_enqueue(f.server, source + 70000, 38000, NULL), VIREO_OK);
    CHECK(memcmp(snapshot, f.server->io.write_scratch, sizeof(snapshot)) == 0 && info(f.server).write_size == 100000);
    vireo_tls_io_budget_t too_small = {16383, 1};
    EXPECT(vireo_tls_connection_send(f.server, &too_small, &progress, NULL), VIREO_RESULT_RANGE);
    EXPECT(vireo_tls_connection_send(f.server, &budget, &progress, NULL), VIREO_OK);
    CHECK(progress.bytes == 0 && memcmp(snapshot, f.server->io.write_scratch, sizeof(snapshot)) == 0);
    size_t received = 0, wants = 2; int64_t deadline = monotonic_ms() + 5000;
    for (size_t round = 0; round < 10000 && received < total && monotonic_ms() < deadline; ++round) {
        received += client_io(f.client, actual + received, total - received, false);
        EXPECT(vireo_tls_connection_send(f.server, &budget, &progress, NULL), VIREO_OK);
        if (progress.stop_reason == VIREO_TLS_IO_STOP_WOULD_BLOCK) { ++wants; }
    }
    CHECK(received == total && info(f.server).write_size == 0 && memcmp(source, actual, total) == 0);
    (void)printf("application WANT_WRITE=%zu; exact %zu bytes after snapshot/compact\n", wants, received);
    free(actual); free(source); release_peer(&f);
}

/** SSL_pending为明文，内核无新事件仍可读取；下一次真实WANT清本地预算续调度。 */
static void real_pending_without_fd_event(void)
{
    peer_fixture_t f = connected(8192, 8192);
    uint8_t source[4096]; memset(source, 0x7B, sizeof(source));
    CHECK(client_io(f.client, source, sizeof(source), true) == sizeof(source));
    vireo_tls_io_budget_t one = {1, 1}, rest = {4095, 1}; vireo_tls_io_progress_t progress;
    EXPECT(vireo_tls_connection_receive(f.server, &one, &progress, NULL), VIREO_OK);
    CHECK(progress.bytes == 1 && SSL_pending(f.server->native) == 4095);
    struct pollfd fd = {f.pair[0], POLLIN, 0}; CHECK(poll(&fd, 1, 0) == 0);
    CHECK(flow(f.server).resume_read);
    EXPECT(vireo_tls_connection_receive(f.server, &rest, &progress, NULL), VIREO_OK); CHECK(progress.bytes == 4095);
    uint8_t const *view; size_t size;
    EXPECT(vireo_tls_connection_read_peek(f.server, &view, &size, NULL), VIREO_OK);
    CHECK(size == sizeof(source) && memcmp(source, view, size) == 0);
    EXPECT(vireo_tls_connection_read_consume(f.server, size, NULL), VIREO_OK);
    EXPECT(vireo_tls_connection_receive(f.server, &one, &progress, NULL), VIREO_OK);
    CHECK(progress.stop_reason == VIREO_TLS_IO_STOP_WOULD_BLOCK && !flow(f.server).resume_read);
    (void)puts("SSL_pending 4095; poll no READ event; plaintext drained exactly"); release_peer(&f);
}

/** 把客户端一条应用记录分两次送入真实socket；partial record pending不能触发立即空转。 */
static void real_partial_record_no_spin(void)
{
    peer_fixture_t f = connected(8192, 8192);
    BIO *wire = BIO_new(BIO_s_mem()); CHECK(wire != NULL);
    SSL_set0_wbio(f.client, wire); /* SSL仍保留原socket rbio，只替换输出，wire由SSL拥有。 */
    uint8_t source[4096], ciphertext[8192]; memset(source, 0x5C, sizeof(source));
    CHECK(client_io(f.client, source, sizeof(source), true) == sizeof(source));
    int bytes = BIO_read(wire, ciphertext, (int)sizeof(ciphertext)); CHECK(bytes > 7);
    CHECK(send(f.pair[1], ciphertext, 7, MSG_NOSIGNAL) == 7);
    vireo_tls_io_budget_t budget = {8192, 1}; vireo_tls_io_progress_t progress;
    EXPECT(vireo_tls_connection_receive(f.server, &budget, &progress, NULL), VIREO_OK);
    CHECK(progress.stop_reason == VIREO_TLS_IO_STOP_WOULD_BLOCK && SSL_pending(f.server->native) == 0);
    CHECK(SSL_has_pending(f.server->native) == 1 && !flow(f.server).resume_read);
    EXPECT(vireo_tls_connection_receive(f.server, &budget, &progress, NULL), VIREO_OK);
    CHECK(progress.bytes == 0 && progress.native_calls == 1 && !flow(f.server).resume_read);
    CHECK(send(f.pair[1], ciphertext + 7, (size_t)bytes - 7, MSG_NOSIGNAL) == bytes - 7);
    EXPECT(vireo_tls_connection_receive(f.server, &budget, &progress, NULL), VIREO_OK); CHECK(progress.bytes == 4096);
    uint8_t const *view; size_t size;
    EXPECT(vireo_tls_connection_read_peek(f.server, &view, &size, NULL), VIREO_OK);
    CHECK(size == 4096 && memcmp(view, source, size) == 0);
    (void)puts("partial record: SSL_has_pending=1, SSL_pending=0, no immediate resume"); release_peer(&f);
}

/** 客户端close_notify正常半关闭，已有明文不丢且服务器仍可反向响应。 */
static void real_close_notify_half_close(void)
{
    peer_fixture_t f = connected(8192, 8192);
    uint8_t message[3] = {'a', 0, 'b'};
    CHECK(client_io(f.client, message, sizeof(message), true) == sizeof(message));
    ERR_clear_error(); int returned = SSL_shutdown(f.client);
    int classification = returned < 0 ? SSL_get_error(f.client, returned) : SSL_ERROR_NONE;
    CHECK(returned == 0 || returned == 1 || classification == SSL_ERROR_WANT_READ || classification == SSL_ERROR_WANT_WRITE);
    ERR_clear_error();
    vireo_tls_io_budget_t budget = {8192, 4}; vireo_tls_io_progress_t progress;
    EXPECT(vireo_tls_connection_receive(f.server, &budget, &progress, NULL), VIREO_OK);
    CHECK(progress.stop_reason == VIREO_TLS_IO_STOP_PEER_EOF && progress.bytes == 3 && info(f.server).read_eof);
    CHECK(info(f.server).read_size == 3 && !flow(f.server).want_read);
    EXPECT(vireo_tls_connection_receive(f.server, &budget, &progress, NULL), VIREO_OK);
    CHECK(progress.native_calls == 0 && progress.stop_reason == VIREO_TLS_IO_STOP_PEER_EOF);
    EXPECT(vireo_tls_connection_enqueue(f.server, message, sizeof(message), NULL), VIREO_OK);
    EXPECT(vireo_tls_connection_send(f.server, &budget, &progress, NULL), VIREO_OK); CHECK(progress.bytes == 3);
    uint8_t response[3]; CHECK(client_io(f.client, response, sizeof(response), false) == 3);
    CHECK(memcmp(response, message, 3) == 0);
    release_peer(&f);
}

/** 裸EOF为协议失败；写断端保存真实errno，终态重复/握手重复均无网络复活。 */
static void real_raw_eof_and_epipe(void)
{
    for (unsigned int writing = 0; writing < 2; ++writing) {
        peer_fixture_t f = connected(8192, 8192);
        SSL_free(f.client); f.client = NULL; CHECK(close(f.pair[1]) == 0); f.pair[1] = -1;
        vireo_tls_io_budget_t budget = {8192, 4}; vireo_tls_io_progress_t progress; vireo_tls_connection_error_t error;
        if (writing != 0) {
            EXPECT(vireo_tls_connection_enqueue(f.server, (uint8_t const *)"x", 1, NULL), VIREO_OK);
            EXPECT(vireo_tls_connection_send(f.server, &budget, &progress, &error), VIREO_RESULT_IO);
            CHECK(error.system_errno == EPIPE || error.system_errno == ECONNRESET);
            (void)printf("application closed-write errno=%d\n", error.system_errno);
        } else {
            EXPECT(vireo_tls_connection_receive(f.server, &budget, &progress, &error), VIREO_RESULT_PROTOCOL);
            CHECK(error.openssl_error_code != 0 && !info(f.server).read_eof);
        }
        vireo_result_t expected = writing != 0 ? VIREO_RESULT_IO : VIREO_RESULT_PROTOCOL;
        EXPECT(vireo_tls_connection_send(f.server, &budget, &progress, &error), expected); CHECK(progress.native_calls == 0);
        vireo_tls_connection_info_t historical;
        EXPECT(vireo_tls_connection_inspect(f.server, &historical, NULL), VIREO_OK); CHECK(historical.handshake_complete);
        vireo_tls_handshake_info_t handshake;
        EXPECT(vireo_tls_connection_handshake_step(f.server, &handshake, NULL), VIREO_OK); CHECK(!handshake.native_called);
        EXPECT(vireo_tls_connection_receive(f.server, &budget, &progress, NULL), expected); CHECK(progress.native_calls == 0);
        release_peer(&f);
    }
}

static void run_exec(char const *mode)
{
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) { execl("/proc/self/exe", "vireo_tls_io_test", mode, (char *)NULL); _exit(127); }
    int status = 0; pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited == -1 && errno == EINTR);
    CHECK(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--real") == 0) {
        struct sigaction action = {0}; action.sa_handler = SIG_IGN; CHECK(sigemptyset(&action.sa_mask) == 0);
        CHECK(sigaction(SIGPIPE, &action, NULL) == 0); size_t before = fd_count();
#define RUN(function) do { function(); (void)puts("[PASS] " #function); } while (0)
        RUN(real_bidirectional_bytes); RUN(real_application_want_write); RUN(real_pending_without_fd_event);
        RUN(real_partial_record_no_spin); RUN(real_close_notify_half_close); RUN(real_raw_eof_and_epipe);
#undef RUN
        CHECK(fd_count() == before); (void)printf("6 real groups passed; fd %zu -> %zu\n", before, fd_count()); return 0;
    }
    CHECK(argc == 1); size_t before = fd_count();
    struct sigaction initial, after; sigset_t initial_mask, after_mask, initial_pending, after_pending;
    CHECK(sigaction(SIGPIPE, NULL, &initial) == 0 && sigprocmask(SIG_BLOCK, NULL, &initial_mask) == 0);
    CHECK(sigpending(&initial_pending) == 0);
#define RUN(function) do { function(); (void)puts("[PASS] " #function); } while (0)
    RUN(configuration_and_arguments); RUN(resource_rollback); RUN(write_snapshot_and_budgets);
    RUN(directions_pressure_and_duplex); RUN(fatal_and_prefix); RUN(signal_and_output_boundaries); RUN(capacity_eof_and_tables);
#undef RUN
    run_exec("--real");
    CHECK(sigaction(SIGPIPE, NULL, &after) == 0 && initial.sa_handler == after.sa_handler);
    CHECK(sigprocmask(SIG_BLOCK, NULL, &after_mask) == 0 && sigpending(&after_pending) == 0);
    CHECK(sigismember(&initial_mask, SIGPIPE) == sigismember(&after_mask, SIGPIPE));
    CHECK(sigismember(&initial_pending, SIGPIPE) == sigismember(&after_pending, SIGPIPE));
    CHECK(fd_count() == before);
    (void)printf("13 groups passed (7 own + 6 real); fd %zu -> %zu; parent SIGPIPE preserved\n", before, fd_count()); return 0;
}
