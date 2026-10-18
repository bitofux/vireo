/*
- PROJECT : VIREO
- FILE    : test_tls_io_prepare.c
- AUTHOR  : bitofux
- DATE    : 2026-10-17
- BRIEF   : 此模块负责：
- -- 握手前准备的原子资源、全部门禁、激活及真实TLS生命周期验证
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

static vireo_tls_io_options_t options(void)
{ return (vireo_tls_io_options_t){128,128,33024,32,31,96,32,96}; }

static vireo_tls_io_info_t inspect(vireo_tls_connection_t *tls)
{
    vireo_tls_io_info_t info;
    EXPECT(vireo_tls_connection_io_inspect(tls, &info, NULL), VIREO_OK);
    return info;
}

/** 本模块计数只覆盖四应用资源和策略检查，不能推导OpenSSL握手内部无分配。 */
typedef struct resources {
    size_t calls, fail_at, live;
    bool fail_oom;
    unsigned int release_order; /**< scratch写/读、FIFO写/读依次形成4321。 */
    void *objects[4];
} resources_t;

static void *resource_allocate(void *context, size_t size)
{
    resources_t *r = context;
    if (++r->calls == r->fail_at) { return NULL; }
    void *p = malloc(size); CHECK(p != NULL && r->calls <= 4);
    r->objects[r->calls-1] = p; ++r->live; return p;
}
static void record_release(resources_t *r, void *p)
{
    CHECK(p != NULL && r->live > 0);
    for (size_t i = 0; i < 4; ++i) {
        if (r->objects[i] == p) {
            r->release_order = r->release_order * 10 + (unsigned int)i + 1;
            r->objects[i] = NULL; --r->live; return;
        }
    }
    CHECK(false);
}
static void resource_free(void *context, void *p)
{ record_release(context, p); free(p); }
static vireo_result_t resource_buffer(void *context, size_t size, vireo_buffer_t **out)
{
    resources_t *r = context;
    if (++r->calls == r->fail_at) { return VIREO_RESULT_NO_MEMORY; }
    CHECK(vireo_buffer_create(size, out) == VIREO_OK && r->calls <= 4);
    r->objects[r->calls-1] = *out; ++r->live; return VIREO_OK;
}
static void resource_buffer_free(void *context, vireo_buffer_t **out)
{ record_release(context, *out); CHECK(vireo_buffer_destroy(out) == VIREO_OK); }
static bool resource_policy(void *context, SSL *native)
{
    resources_t *r = context;
    if (++r->calls == r->fail_at) {
        if (r->fail_oom) { ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE); }
        return false;
    }
    (void)SSL_clear_mode(native, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    (void)SSL_set_mode(native, SSL_MODE_AUTO_RETRY); SSL_set_read_ahead(native, 0);
    SSL_set_quiet_shutdown(native, 0); (void)SSL_clear_options(native, SSL_OP_IGNORE_UNEXPECTED_EOF);
    return true;
}
static vireo_tls_io_config_ops_t resource_ops(resources_t *r)
{
    return (vireo_tls_io_config_ops_t){r,resource_allocate,resource_free,resource_buffer,
        resource_buffer_free,resource_policy};
}

static void arguments(void)
{
    int pair[2]; vireo_tls_connection_t *tls = make_server(pair, 0);
    vireo_tls_io_options_t good = options(); resources_t r = {0};
    vireo_tls_io_config_ops_t ops = resource_ops(&r);
    EXPECT(vireo_tls_connection_io_prepare(NULL, &good, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tls_connection_io_prepare(tls, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    for (unsigned int i = 0; i < 6; ++i) {
        vireo_tls_io_config_ops_t bad = ops;
        if (i == 1) bad.allocate = NULL;
        if (i == 2) bad.deallocate = NULL;
        if (i == 3) bad.buffer_create = NULL;
        if (i == 4) bad.buffer_destroy = NULL;
        if (i == 5) bad.prepare = NULL;
        EXPECT(vireo_tls_connection_io_prepare_with_ops(tls, &good, NULL, i == 0 ? NULL : &bad),
            VIREO_RESULT_INVALID_ARGUMENT);
    }
    for (unsigned int i = 0; i < 14; ++i) {
        vireo_tls_io_options_t bad = good; vireo_result_t result = VIREO_RESULT_RANGE;
        if (i == 0) { bad.read_capacity = SIZE_MAX; result = VIREO_RESULT_OVERFLOW; }
        if (i == 1) { bad.write_capacity = SIZE_MAX-128; result = VIREO_RESULT_OVERFLOW; }
        if (i == 2) bad.read_capacity = 0;
        if (i == 3) bad.write_capacity = 0;
        if (i == 4) bad.max_buffer_bytes = 0;
        if (i == 5) bad.max_buffer_bytes = 33023;
        if (i == 6) bad.max_buffer_bytes = VIREO_TLS_IO_MAX_BUFFER_BYTES+1;
        if (i == 7) bad.max_read_unit_bytes = 0;
        if (i == 8) bad.max_read_unit_bytes = 129;
        if (i == 9) bad.read_low = 30;
        if (i == 10) bad.read_low = 96;
        if (i == 11) bad.read_high = 129;
        if (i == 12) bad.write_low = 96;
        if (i == 13) bad.write_high = 129;
        ERR_raise(ERR_LIB_USER, 901); unsigned long old = ERR_peek_error();
        EXPECT(vireo_tls_connection_io_prepare_with_ops(tls, &bad, NULL, &ops), result);
        CHECK(ERR_peek_error() == old && r.calls == 0); ERR_clear_error();
        CHECK(inspect(tls).state == VIREO_TLS_IO_DISABLED);
    }
    /* 原入口INITIAL仍BUSY；prepare不等同放宽configure。 */
    EXPECT(vireo_tls_connection_io_configure(tls, &good, NULL), VIREO_RESULT_BUSY);
    release_server(&tls, pair);
}

static void rollback(void)
{
    for (size_t failure = 1; failure <= 6; ++failure) {
        int pair[2]; vireo_tls_connection_t *tls = make_server(pair, 0);
        EXPECT(vireo_tls_connection_handshake_deadline_arm(tls, 100, 200, NULL), VIREO_OK);
        resources_t r = {.fail_at = failure}; vireo_tls_io_config_ops_t ops = resource_ops(&r);
        vireo_tls_io_options_t opts = options(); vireo_tls_connection_error_t error;
        vireo_result_t result = failure <= 4 ? VIREO_RESULT_NO_MEMORY :
            (failure == 5 ? VIREO_RESULT_INTERNAL : VIREO_OK);
        EXPECT(vireo_tls_connection_io_prepare_with_ops(tls, &opts, &error, &ops), result);
        CHECK(tls->state == VIREO_TLS_HANDSHAKE_INITIAL && !tls->handshake_native_attempted);
        CHECK(tls->deadline_ns == 200 && tls->last_now_ns == 100 && tls->deadline_armed);
        if (failure <= 5) {
            unsigned int orders[] = {0,0,1,21,321,4321};
            CHECK(r.live == 0 && r.release_order == orders[failure]);
            CHECK(inspect(tls).state == VIREO_TLS_IO_DISABLED && tls->io.read_buffer == NULL);
            CHECK(error.stage == VIREO_TLS_CONNECTION_STAGE_CONFIGURE_IO);
            /* 同一对象可以重试，原期限不变；改走生产表，不延用计数表。 */
            EXPECT(vireo_tls_connection_io_prepare(tls, &opts, NULL), VIREO_OK);
        } else { CHECK(r.live == 4); }
        release_server(&tls, pair); CHECK(r.live == 0);
        if (failure == 6) CHECK(r.release_order == 4321);
    }
    int pair[2]; vireo_tls_connection_t *tls = make_server(pair, 0);
    resources_t r = {.fail_at=5,.fail_oom=true}; vireo_tls_io_config_ops_t ops = resource_ops(&r);
    vireo_tls_io_options_t opts = options(); vireo_tls_connection_error_t error;
    EXPECT(vireo_tls_connection_io_prepare_with_ops(tls,&opts,&error,&ops), VIREO_RESULT_NO_MEMORY);
    CHECK(error.openssl_error_code != 0 && ERR_peek_error() == 0 && r.live == 0);
    release_server(&tls, pair);
}

/** 准备态必须在任何信号查询/原生操作前拒绝，own表若被调用立即失败。 */
static int forbidden_policy(void *c, bool *out)
{ (void)c; (void)out; CHECK(false); return -1; }
static int forbidden_read(void *c, SSL *s, void *p, size_t n, size_t *out)
{ (void)c;(void)s;(void)p;(void)n;(void)out; CHECK(false);return 0; }
static int forbidden_write(void *c, SSL *s, void const *p, size_t n, size_t *out)
{ (void)c;(void)s;(void)p;(void)n;(void)out; CHECK(false);return 0; }
static int forbidden_error(void *c, SSL *s, int n)
{ (void)c;(void)s;(void)n;CHECK(false);return SSL_ERROR_SSL; }

static void check_gates(vireo_tls_connection_t *tls)
{
    vireo_tls_io_budget_t budget = {128,1}; vireo_tls_io_progress_t report;
    memset(&report,0xA7,sizeof(report)); unsigned char saved[sizeof(report)];
    memcpy(saved,&report,sizeof(saved));
    vireo_tls_io_ops_t ops = {NULL,forbidden_policy,forbidden_read,forbidden_write,forbidden_error};
    for (unsigned int i = 0; i < 2; ++i) {
        EXPECT(vireo_tls_connection_io_with_ops(tls,&budget,&report,NULL,i != 0,&ops),VIREO_RESULT_BUSY);
        CHECK(memcmp(saved,&report,sizeof(saved)) == 0);
    }
    uint8_t const *view = (uint8_t const *)&budget; size_t size = 111;
    EXPECT(vireo_tls_connection_read_peek(tls,&view,&size,NULL),VIREO_RESULT_BUSY);
    CHECK(view == (uint8_t const *)&budget && size == 111);
    EXPECT(vireo_tls_connection_read_consume(tls,0,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tls_connection_read_consume(tls,1,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tls_connection_enqueue(tls,NULL,0,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tls_connection_enqueue(tls,(uint8_t const *)"x",1,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tls_connection_receive(tls,&budget,&report,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tls_connection_send(tls,&budget,&report,NULL),VIREO_RESULT_BUSY);
    CHECK(memcmp(saved,&report,sizeof(saved)) == 0);
    vireo_tls_io_flow_t flow;
    EXPECT(vireo_tls_connection_flow_refresh(tls,&flow,NULL),VIREO_OK);
    CHECK(!flow.read_pressure && !flow.write_pressure && !flow.application_read_enabled);
    CHECK(!flow.want_read && !flow.want_write && !flow.resume_read && !flow.resume_write);
    CHECK(flow.priority_retry == VIREO_TLS_IO_OPERATION_NONE);
    EXPECT(vireo_tls_connection_close_request(tls,100,200,NULL),VIREO_RESULT_BUSY);
}

static void prepared_and_timeout(void)
{
    int pair[2]; vireo_tls_connection_t *tls = make_server(pair,0);
    vireo_tls_io_options_t opts = options();
    EXPECT(vireo_tls_connection_handshake_deadline_arm(tls,100,200,NULL),VIREO_OK);
    EXPECT(vireo_tls_connection_io_prepare(tls,&opts,NULL),VIREO_OK);
    vireo_tls_io_info_t before = inspect(tls);
    CHECK(before.state == VIREO_TLS_IO_PREPARED && before.buffer_bytes == 33024);
    CHECK(before.read_buffer.capacity == 128 && before.write_buffer.capacity == 128);
    CHECK(before.read_buffer.tail_space == 128 && before.write_buffer.tail_space == 128);
    CHECK(before.read_size == 0 && before.write_size == 0 && !before.read_eof);
    unsigned char byte; CHECK(recv(pair[1],&byte,1,MSG_DONTWAIT) == -1 && errno == EAGAIN);
    check_gates(tls);
    EXPECT(vireo_tls_connection_io_prepare(tls,&opts,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tls_connection_io_configure(tls,&opts,NULL),VIREO_RESULT_BUSY);
    vireo_tls_handshake_info_t step;
    EXPECT(vireo_tls_connection_handshake_step_at(tls,200,&step,NULL),VIREO_RESULT_TIMEOUT);
    CHECK(!step.native_called && !tls->handshake_native_attempted && inspect(tls).state == VIREO_TLS_IO_PREPARED);
    check_gates(tls);
    EXPECT(vireo_tls_connection_io_prepare(tls,&opts,NULL),VIREO_RESULT_BUSY);
    release_server(&tls,pair);
}

static void real_activation(void)
{
    peer_fixture_t f = make_peer(0,true,"vireo-034-test.invalid",false);
    resources_t r = {0}; vireo_tls_io_config_ops_t ops = resource_ops(&r);
    vireo_tls_io_options_t opts = options();
    EXPECT(vireo_tls_connection_io_prepare_with_ops(f.server,&opts,NULL,&ops),VIREO_OK);
    vireo_buffer_t *read = f.server->io.read_buffer, *write = f.server->io.write_buffer;
    uint8_t *read_scratch = f.server->io.read_scratch, *write_scratch = f.server->io.write_scratch;
    EXPECT(drive(&f),VIREO_OK);
    CHECK(r.calls == 5 && r.live == 4 && f.read_waits != 0);
    CHECK(f.server->io.read_buffer == read && f.server->io.write_buffer == write);
    CHECK(f.server->io.read_scratch == read_scratch && f.server->io.write_scratch == write_scratch);
    CHECK(inspect(f.server).state == VIREO_TLS_IO_OPEN && SSL_get_verify_result(f.client) == X509_V_OK);
    CHECK(SSL_version(f.client) == TLS1_3_VERSION);
    EXPECT(vireo_tls_connection_io_prepare(f.server,&opts,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tls_connection_io_configure(f.server,&opts,NULL),VIREO_RESULT_BUSY);
    vireo_tls_handshake_info_t report;
    EXPECT(vireo_tls_connection_handshake_step(f.server,&report,NULL),VIREO_OK);
    CHECK(!report.native_called && r.calls == 5);
    release_peer(&f); CHECK(r.live == 0 && r.release_order == 4321);
}

static void old_path_and_fatal(void)
{
    peer_fixture_t f = make_peer(0,true,"vireo-034-test.invalid",false);
    vireo_tls_handshake_info_t step; vireo_tls_io_options_t opts = options();
    EXPECT(vireo_tls_connection_handshake_step(f.server,&step,NULL),VIREO_OK);
    CHECK(step.state == VIREO_TLS_HANDSHAKE_HANDSHAKING);
    EXPECT(vireo_tls_connection_io_prepare(f.server,&opts,NULL),VIREO_RESULT_BUSY);
    EXPECT(drive(&f),VIREO_OK); CHECK(inspect(f.server).state == VIREO_TLS_IO_DISABLED);
    EXPECT(vireo_tls_connection_io_configure(f.server,&opts,NULL),VIREO_OK);
    CHECK(inspect(f.server).state == VIREO_TLS_IO_OPEN); release_peer(&f);
    f = make_peer(0,true,"wrong.invalid",false);
    EXPECT(vireo_tls_connection_io_prepare(f.server,&opts,NULL),VIREO_OK);
    EXPECT(drive(&f),VIREO_RESULT_PROTOCOL);
    CHECK(f.server->state == VIREO_TLS_HANDSHAKE_FAILED && inspect(f.server).state == VIREO_TLS_IO_PREPARED);
    check_gates(f.server); release_peer(&f);
}

int main(void)
{
    size_t before = fd_count(); struct sigaction old, ignored = {0};
    ignored.sa_handler = SIG_IGN; CHECK(sigemptyset(&ignored.sa_mask) == 0);
    CHECK(sigaction(SIGPIPE,&ignored,&old) == 0);
    arguments(); rollback(); prepared_and_timeout(); real_activation(); old_path_and_fatal();
    CHECK(sigaction(SIGPIPE,&old,NULL) == 0); size_t after = fd_count(); CHECK(before == after);
    printf("TLS prepare: 5 groups passed; fd %zu -> %zu; four resource addresses unchanged\n",before,after);
    return 0;
}


