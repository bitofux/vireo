/*
- PROJECT : VIREO
- FILE    : test_connection_tls.c
- AUTHOR  : bitofux
- DATE    : 2026-10-17
- BRIEF   : 单连接TLS组合的own资源回滚、真实唯一FIFO/帧/重试及关闭验证
 */
#define _GNU_SOURCE
#include "net/connection_internal.h"
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
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #test); abort(); \
} } while (0)
#define EXPECT(call, expected) do { errno = ECHILD; \
    vireo_result_t actual_result = (call); CHECK(actual_result == (expected)); CHECK(errno == ECHILD); \
} while (0)

/** 本测试的有限fd配对证据，不外推一般资源安全。 */
static size_t fd_count(void)
{
    DIR *dir = opendir("/proc/self/fd"); CHECK(dir != NULL);
    size_t count = 0; struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) { ++count; }
    }
    CHECK(closedir(dir) == 0); return count;
}

static vireo_tls_context_t *make_context(void)
{
    vireo_tls_context_options_t options = {
        fixture_leaf, sizeof(fixture_leaf)-1, fixture_key, sizeof(fixture_key)-1, 4096
    };
    vireo_tls_context_t *context = NULL;
    EXPECT(vireo_tls_context_create_server(&options, &context, NULL), VIREO_OK);
    return context;
}

/** own seam只验证资源故障，绝不伪造SSL状态或使用TLS private布局。 */
typedef struct resources {
    size_t allocations; /**< connection控制块申请数。 */
    size_t frees;       /**< 申请成功后的配对释放数。 */
    size_t closes;      /**< fd最后单次close数。 */
    bool fail_allocate; /**< 原生前分配拒绝。 */
    bool fail_close;    /**< 实际close后报EINTR并复用fd数值，验证不重试。 */
    int replacement;    /**< close后新打开的独立fd owner。 */
} resources_t;

static void *tracked_allocate(void *context, size_t bytes)
{
    resources_t *r = context; ++r->allocations;
    return r->fail_allocate ? NULL : malloc(bytes);
}
static void tracked_free(void *context, void *memory)
{ resources_t *r = context; ++r->frees; free(memory); }
static int tracked_close(void *context, int fd)
{
    resources_t *r = context; ++r->closes; CHECK(close(fd) == 0);
    if (r->fail_close) {
        r->replacement = open("/dev/null", O_RDONLY | O_CLOEXEC);
        CHECK(r->replacement == fd); errno = EINTR; return -1;
    }
    return 0;
}
/* 以下raw依赖必须从未被TLS路径调用，否则立即失败。 */
static int forbidden_flags(void *c, int fd, int cmd)
{ (void)c; (void)fd; (void)cmd; CHECK(false); return -1; }
static int forbidden_type(void *c, int fd, int *type)
{ (void)c; (void)fd; (void)type; CHECK(false); return -1; }
static int forbidden_peer(void *c, int fd)
{ (void)c; (void)fd; CHECK(false); return -1; }
static vireo_result_t forbidden_buffer(void *c, size_t cap, vireo_buffer_t **out)
{ (void)c; (void)cap; (void)out; CHECK(false); return VIREO_RESULT_INTERNAL; }
static void forbidden_destroy(void *c, vireo_buffer_t **owner)
{ (void)c; (void)owner; CHECK(false); }
static ssize_t forbidden_receive(void *c, int fd, void *p, size_t n, int flags)
{ (void)c; (void)fd; (void)p; (void)n; (void)flags; CHECK(false); return -1; }
static ssize_t forbidden_send(void *c, int fd, void const *p, size_t n, int flags)
{ (void)c; (void)fd; (void)p; (void)n; (void)flags; CHECK(false); return -1; }
static vireo_connection_ops_t tracked_ops(resources_t *r)
{
    return (vireo_connection_ops_t){r, tracked_allocate, tracked_free, forbidden_flags,
        forbidden_type, forbidden_peer, tracked_close, forbidden_buffer, forbidden_destroy,
        forbidden_receive, forbidden_send};
}

/** 有真实fd及生产TLS创建的故障边界；失败不转移fd，不创建raw双buffer。 */
static void resource_contract(void)
{
    int pair[2]; CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
    int original = pair[0]; vireo_connection_t *connection = NULL;
    vireo_tls_context_t *context = make_context(); vireo_tls_connection_options_t options = {4096};
    resources_t r = {0}; vireo_connection_ops_t ops = tracked_ops(&r);
    vireo_connection_error_t error;
    EXPECT(vireo_connection_create_tls_server(NULL, &options, &pair[0], &connection, &error),
        VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(pair[0] == original && connection == NULL);
    r.fail_allocate = true;
    EXPECT(vireo_connection_create_tls_server_with_ops(context, &options, &pair[0], &ops,
        &connection, &error), VIREO_RESULT_NO_MEMORY);
    CHECK(error.stage == VIREO_CONNECTION_STAGE_ALLOCATE_CONTROL && r.frees == 0);
    r.fail_allocate = false; options.max_wrapper_bytes = 1;
    EXPECT(vireo_connection_create_tls_server_with_ops(context, &options, &pair[0], &ops,
        &connection, &error), VIREO_RESULT_RANGE);
    CHECK(pair[0] == original && connection == NULL && r.frees == 1 && r.closes == 0);
    CHECK(error.stage == VIREO_CONNECTION_STAGE_TLS && error.tls_error.system_errno == 0);
    options.max_wrapper_bytes = 4096;
    CHECK(fcntl(pair[0], F_SETFL, 0) == 0);
    EXPECT(vireo_connection_create_tls_server_with_ops(context, &options, &pair[0], &ops,
        &connection, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(pair[0] == original && connection == NULL && r.frees == 2 && r.closes == 0);
    CHECK(fcntl(pair[0], F_SETFL, O_NONBLOCK) == 0);
    EXPECT(vireo_connection_create_tls_server_with_ops(context, &options, &pair[0], &ops,
        &connection, &error), VIREO_OK);
    CHECK(pair[0] == -1 && connection != NULL && error.tls_error.stage == 0);
    EXPECT(vireo_tls_context_destroy(&context, NULL), VIREO_OK);
    vireo_tls_connection_t *first = NULL, *second = NULL;
    EXPECT(vireo_connection_tls_borrow(connection, &first), VIREO_OK);
    EXPECT(vireo_connection_tls_borrow(connection, &second), VIREO_OK); CHECK(first == second);
    first = NULL; second = NULL; /* 结束借用，不destroy借来的owner。 */
    r.fail_close = true;
    EXPECT(vireo_connection_destroy(&connection, &error), VIREO_RESULT_IO);
    CHECK(connection == NULL && r.closes == 1 && r.frees == 3);
    CHECK(error.stage == VIREO_CONNECTION_STAGE_CLOSE_SOCKET && error.system_errno == EINTR);
    CHECK(error.tls_error.stage == 0 && fcntl(r.replacement, F_GETFD) >= 0);
    CHECK(close(r.replacement) == 0 && close(pair[1]) == 0);
}

static void borrow_raw(void)
{
    int pair[2]; CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
    vireo_connection_t *connection = NULL; vireo_connection_options_t options = {32,32,64};
    EXPECT(vireo_connection_create(&options, &pair[0], &connection, NULL), VIREO_OK);
    vireo_tls_connection_t *sentinel = (void *)&options, *borrow = sentinel;
    EXPECT(vireo_connection_tls_borrow(connection, &borrow), VIREO_RESULT_NOT_FOUND);
    CHECK(borrow == sentinel);
    EXPECT(vireo_connection_tls_borrow(NULL, &borrow), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_connection_tls_borrow(connection, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_connection_info_t info; EXPECT(vireo_connection_inspect(connection, &info), VIREO_OK);
    CHECK(info.transport == VIREO_CONNECTION_TRANSPORT_RAW && info.buffer_capacity_bytes == 64);
    EXPECT(vireo_connection_destroy(&connection, NULL), VIREO_OK); CHECK(close(pair[1]) == 0);
}

/** 客户端仅为可信TLS互操作测试，不属于产品client实现。 */
typedef struct peer {
    vireo_connection_t *connection; /**< 唯一组合owner；负责server_fd。 */
    vireo_tls_connection_t *tls;    /**< 上述组合内串行借用，不可destroy。 */
    SSL *client;                  /**< 测试客户端native owner，BIO不关fd。 */
    int server_fd;                 /**< 只借用于poll/观测；不能close。 */
    int client_fd;                 /**< 测试对端唯一fd owner。 */
} peer_t;

static peer_t make_peer(void)
{
    peer_t p = {0}; int pair[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
    p.server_fd = pair[0]; p.client_fd = pair[1];
    vireo_tls_context_t *context = make_context(); vireo_tls_connection_options_t options = {4096};
    EXPECT(vireo_connection_create_tls_server(context, &options, &pair[0], &p.connection, NULL), VIREO_OK);
    CHECK(pair[0] == -1);
    EXPECT(vireo_tls_context_destroy(&context, NULL), VIREO_OK);
    EXPECT(vireo_connection_tls_borrow(p.connection, &p.tls), VIREO_OK);
    SSL_CTX *client_context = SSL_CTX_new(TLS_client_method()); CHECK(client_context != NULL);
    CHECK(SSL_CTX_set_min_proto_version(client_context, TLS1_3_VERSION) == 1);
    CHECK(SSL_CTX_set_max_proto_version(client_context, TLS1_3_VERSION) == 1);
    SSL_CTX_set_verify(client_context, SSL_VERIFY_PEER, NULL);
    BIO *root_bio = BIO_new_mem_buf(fixture_root, (int)sizeof(fixture_root)-1); CHECK(root_bio != NULL);
    X509 *root = PEM_read_bio_X509(root_bio, NULL, NULL, NULL); CHECK(root != NULL);
    CHECK(X509_STORE_add_cert(SSL_CTX_get_cert_store(client_context), root) == 1);
    X509_free(root); CHECK(BIO_free(root_bio) == 1);
    p.client = SSL_new(client_context); CHECK(p.client != NULL); SSL_CTX_free(client_context);
    X509_VERIFY_PARAM_set_time(SSL_get0_param(p.client), (time_t)1800000000);
    CHECK(SSL_set1_host(p.client, "vireo-034-test.invalid") == 1);
    BIO *bio = BIO_new_socket(p.client_fd, BIO_NOCLOSE); CHECK(bio != NULL);
    SSL_set_bio(p.client, bio, bio); SSL_set_connect_state(p.client);
    return p;
}
static void release_peer(peer_t *p)
{
    SSL_free(p->client); p->client = NULL; p->tls = NULL;
    EXPECT(vireo_connection_destroy(&p->connection, NULL), VIREO_OK);
    CHECK(fcntl(p->server_fd, F_GETFD) == -1 && errno == EBADF);
    CHECK(close(p->client_fd) == 0);
}
static vireo_monotonic_ns_t now_ns(void)
{
    vireo_monotonic_ns_t now;
    EXPECT(vireo_clock_monotonic_now(&now, NULL), VIREO_OK); return now;
}
static void handshake(peer_t *p)
{
    vireo_monotonic_ns_t now = now_ns();
    EXPECT(vireo_tls_connection_handshake_deadline_arm(p->tls, now, now+UINT64_C(5000000000), NULL), VIREO_OK);
    bool client_done = false; vireo_tls_handshake_info_t report = {0};
    for (size_t round = 0; round < 2048; ++round) {
        if (!client_done) {
            ERR_clear_error(); int returned = SSL_do_handshake(p->client);
            int why = returned == 1 ? SSL_ERROR_NONE : SSL_get_error(p->client, returned);
            CHECK(why == SSL_ERROR_NONE || why == SSL_ERROR_WANT_READ || why == SSL_ERROR_WANT_WRITE);
            client_done = returned == 1;
        }
        EXPECT(vireo_tls_connection_handshake_step_at(p->tls, now_ns(), &report, NULL), VIREO_OK);
        if (client_done && report.state == VIREO_TLS_HANDSHAKE_ESTABLISHED) {
            CHECK(SSL_version(p->client) == TLS1_3_VERSION && SSL_get_verify_result(p->client) == X509_V_OK);
            return;
        }
        struct pollfd fds[2] = {{p->server_fd, POLLIN | POLLOUT,0}, {p->client_fd,POLLIN | POLLOUT,0}};
        CHECK(poll(fds, 2, 1) >= 0);
    }
    CHECK(false);
}
static void configure(peer_t *p, size_t read_capacity, size_t write_capacity)
{
    vireo_tls_io_options_t options = {read_capacity, write_capacity,
        read_capacity+write_capacity+32768, 128,127,read_capacity,0,write_capacity};
    EXPECT(vireo_tls_connection_io_configure(p->tls, &options, NULL), VIREO_OK);
}
static vireo_tls_io_info_t io_info(peer_t *p)
{
    vireo_tls_io_info_t info; EXPECT(vireo_tls_connection_io_inspect(p->tls, &info, NULL), VIREO_OK);
    return info;
}
static vireo_connection_info_t connection_info(peer_t *p)
{
    vireo_connection_info_t info; EXPECT(vireo_connection_inspect(p->connection, &info), VIREO_OK);
    return info;
}
static void receive_bytes(peer_t *p, size_t expected)
{
    vireo_tls_io_budget_t budget = {512,16}; vireo_tls_io_progress_t progress;
    EXPECT(vireo_tls_connection_receive(p->tls, &budget, &progress, NULL), VIREO_OK);
    CHECK(progress.bytes == expected);
}
static void client_write(peer_t *p, uint8_t const *bytes, size_t size)
{
    size_t sent = 0; ERR_clear_error(); CHECK(SSL_write_ex(p->client, bytes, size, &sent) == 1);
    CHECK(sent == size);
}
static size_t client_read(peer_t *p, uint8_t *out, size_t capacity)
{
    size_t bytes = 0; ERR_clear_error(); int returned = SSL_read_ex(p->client, out, capacity, &bytes);
    int why = returned == 1 ? SSL_ERROR_NONE : SSL_get_error(p->client, returned);
    CHECK(why == SSL_ERROR_NONE || why == SSL_ERROR_WANT_READ || why == SSL_ERROR_WANT_WRITE);
    return bytes;
}
static void make_frame(uint8_t wire[32], uint32_t sequence, bool response)
{
    vireo_protocol_header_t header = {0}; header.command = VIREO_COMMAND_PING; header.sequence = sequence;
    if (response) { header.flags = VIREO_PROTOCOL_FLAG_RESPONSE; }
    EXPECT(vireo_protocol_header_encode(&header, wire, 32), VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(wire,32,NULL,0,&header.crc32c), VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&header, wire,32), VIREO_OK);
}
static vireo_connection_frame_info_t parse(peer_t *p, size_t max_frame, vireo_result_t expected,
    vireo_connection_frame_view_t views[4], vireo_connection_frame_error_t *error)
{
    vireo_connection_frame_options_t options = {VIREO_CONNECTION_FRAME_REQUEST,max_frame};
    vireo_connection_frame_budget_t budget = {4,512}; vireo_connection_frame_info_t progress = {0};
    EXPECT(vireo_connection_frames_peek(p->connection,&options,&budget,views,4,&progress,error),expected);
    return progress;
}

static void mode_gates(peer_t *p)
{
    vireo_connection_info_t before = connection_info(p);
    vireo_connection_receive_budget_t rb = {512,8}; vireo_connection_send_budget_t sb = {512,8};
    vireo_connection_receive_info_t receive = {7,8,VIREO_CONNECTION_RECEIVE_STOP_EOF};
    vireo_connection_send_info_t send = {9,10,VIREO_CONNECTION_SEND_STOP_EMPTY};
    vireo_connection_error_t error;
    EXPECT(vireo_connection_receive(p->connection,&rb,&receive,&error), VIREO_RESULT_BUSY);
    CHECK(receive.received_bytes == 7 && receive.recv_calls == 8 && error.tls_error.stage == 0);
    EXPECT(vireo_connection_send(p->connection,&sb,&send,&error), VIREO_RESULT_BUSY);
    CHECK(send.sent_bytes == 9 && send.send_calls == 10);
    vireo_connection_flow_options_t flow = {128,127,512,0,512};
    EXPECT(vireo_connection_flow_configure(p->connection,&flow,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_connection_flow_refresh(p->connection,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_connection_flow_disable(p->connection,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_connection_request_close(p->connection,VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_connection_request_close(p->connection,VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
        VIREO_CONNECTION_CLOSE_REASON_IO,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_connection_close_refresh(p->connection,NULL),VIREO_RESULT_BUSY);
    vireo_connection_info_t after = connection_info(p);
    CHECK(after.loop_attached == before.loop_attached && after.loop_interests == before.loop_interests);
    CHECK(!after.flow_enabled && after.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    CHECK(after.read_buffer.readable_size == before.read_buffer.readable_size);
    CHECK(after.write_buffer.readable_size == before.write_buffer.readable_size);
}

static void disabled_contract(void)
{
    peer_t p = make_peer(); vireo_connection_info_t state = connection_info(&p);
    CHECK(state.transport == VIREO_CONNECTION_TRANSPORT_TLS && state.buffer_capacity_bytes == 0);
    CHECK(state.read_buffer.capacity == 0 && state.write_buffer.capacity == 0 && state.max_buffer_bytes == 0);
    uint8_t const *bytes = (void *)&p; size_t size = 123;
    EXPECT(vireo_connection_read_peek(p.connection,&bytes,&size),VIREO_RESULT_BUSY);
    CHECK(bytes == (void *)&p && size == 123);
    EXPECT(vireo_connection_read_consume(p.connection,0),VIREO_RESULT_BUSY);
    vireo_connection_error_t error;
    EXPECT(vireo_connection_write_enqueue(p.connection,NULL,0,&error),VIREO_RESULT_BUSY);
    CHECK(error.stage == VIREO_CONNECTION_STAGE_TLS && error.tls_error.stage == 0);
    vireo_connection_frame_options_t options = {VIREO_CONNECTION_FRAME_REQUEST,128};
    vireo_connection_frame_budget_t budget = {1,128}; vireo_connection_frame_view_t view = {0};
    vireo_connection_frame_info_t report = {23,45,VIREO_CONNECTION_FRAME_STOP_EOF};
    EXPECT(vireo_connection_frames_peek(p.connection,&options,&budget,&view,1,&report,NULL),VIREO_RESULT_BUSY);
    CHECK(report.frame_count == 23 && report.frame_bytes == 45);
    mode_gates(&p); release_peer(&p);
}

static void self_detach(vireo_connection_t *connection, uint32_t events, void *context)
{
    peer_t *p = context; CHECK(connection == p->connection && events != 0);
    EXPECT(vireo_connection_detach(connection,NULL),VIREO_OK);
    EXPECT(vireo_connection_destroy(&p->connection,NULL),VIREO_RESULT_BUSY);
    CHECK(p->connection != NULL);
}
static void binding_contract(void)
{
    peer_t p = make_peer();
    vireo_event_loop_t *loop = NULL; vireo_event_loop_options_t options = {4,65536,4};
    EXPECT(vireo_event_loop_create(&options,&loop,NULL),VIREO_OK);
    EXPECT(vireo_connection_attach(p.connection,loop,VIREO_EPOLL_INTEREST_WRITE,self_detach,&p,NULL),VIREO_OK);
    EXPECT(vireo_connection_destroy(&p.connection,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_connection_set_interests(p.connection,VIREO_EPOLL_INTEREST_READ,NULL),VIREO_OK);
    mode_gates(&p);
    EXPECT(vireo_connection_set_interests(p.connection,VIREO_EPOLL_INTEREST_WRITE,NULL),VIREO_OK);
    vireo_event_loop_run_info_t report;
    EXPECT(vireo_event_loop_run_once(loop,0,&report,NULL),VIREO_OK);
    CHECK(!connection_info(&p).loop_attached);
    EXPECT(vireo_event_loop_destroy(&loop,NULL),VIREO_OK); release_peer(&p);
}

/** 同一FIFO、跨层view、半包/粘包/有效前缀及帧水位上限。 */
static void framing_contract(void)
{
    peer_t p = make_peer(); handshake(&p); configure(&p,512,512);
    uint8_t requests[96]; for (uint32_t i=0;i<3;++i) { make_frame(requests+32*i,i+1,false); }
    client_write(&p,requests,13); receive_bytes(&p,13);
    vireo_connection_frame_view_t views[4]; vireo_connection_frame_error_t error;
    vireo_connection_frame_info_t parsed = parse(&p,128,VIREO_OK,views,&error);
    CHECK(parsed.frame_count == 0 && parsed.stop_reason == VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
    client_write(&p,requests+13,83); mode_gates(&p); receive_bytes(&p,83);
    uint8_t const *via_connection, *via_tls; size_t n, m;
    EXPECT(vireo_connection_read_peek(p.connection,&via_connection,&n),VIREO_OK);
    EXPECT(vireo_tls_connection_read_peek(p.tls,&via_tls,&m,NULL),VIREO_OK);
    CHECK(via_connection == via_tls && n == 96 && m == n && memcmp(via_connection,requests,n)==0);
    parsed=parse(&p,128,VIREO_OK,views,&error);
    CHECK(parsed.frame_count == 3 && parsed.frame_bytes == 96 && views[2].header.sequence == 3);
    parsed=parse(&p,129,VIREO_RESULT_RANGE,views,&error); CHECK(parsed.frame_count == 0);
    EXPECT(vireo_connection_read_consume(p.connection,32),VIREO_OK);
    CHECK(io_info(&p).read_size == 64);
    vireo_connection_info_t state=connection_info(&p); vireo_tls_io_info_t io=io_info(&p);
    CHECK(state.read_buffer.tail_space == io.read_buffer.tail_space && state.read_buffer.readable_size==64);
    CHECK(state.read_buffer.tail_space < state.read_buffer.capacity-state.read_buffer.readable_size);
    EXPECT(vireo_tls_connection_read_consume(p.tls,64,NULL),VIREO_OK);
    CHECK(connection_info(&p).read_buffer.readable_size == 0);
    uint8_t invalid[64]; memcpy(invalid,requests,64); invalid[63]^=1;
    client_write(&p,invalid,64); receive_bytes(&p,64);
    parsed=parse(&p,128,VIREO_RESULT_PROTOCOL,views,&error);
    CHECK(parsed.frame_count==1 && parsed.frame_bytes==32 && error.issue==VIREO_CONNECTION_FRAME_ISSUE_CODEC);
    EXPECT(vireo_connection_read_consume(p.connection,64),VIREO_OK); release_peer(&p);
}

static void response_contract(void)
{
    peer_t p=make_peer(); handshake(&p); configure(&p,512,128);
    uint8_t responses[96]; for (uint32_t i=0;i<3;++i) { make_frame(responses+32*i,i+1,true); }
    EXPECT(vireo_connection_write_enqueue(p.connection,responses,96,NULL),VIREO_OK);
    CHECK(io_info(&p).write_size==96 && connection_info(&p).write_buffer.readable_size==96);
    EXPECT(vireo_connection_write_enqueue(p.connection,responses,64,NULL),VIREO_RESULT_RANGE);
    CHECK(io_info(&p).write_size==96);
    vireo_tls_io_budget_t budget={32,1}; vireo_tls_io_progress_t progress;
    EXPECT(vireo_tls_connection_send(p.tls,&budget,&progress,NULL),VIREO_OK); CHECK(progress.bytes==32);
    vireo_connection_info_t info=connection_info(&p);
    CHECK(info.write_buffer.readable_size==64 && info.write_buffer.tail_space==32);
    CHECK(info.max_buffer_bytes==640 && info.buffer_capacity_bytes==640);
    budget.max_bytes=128;
    EXPECT(vireo_tls_connection_send(p.tls,&budget,&progress,NULL),VIREO_OK); CHECK(progress.bytes==64);
    uint8_t actual[96]; size_t received=0;
    for(size_t i=0;i<64 && received<96;++i) { received+=client_read(&p,actual+received,96-received); }
    CHECK(received==96 && memcmp(actual,responses,96)==0);
    vireo_protocol_header_t header; vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_header_decode(actual,32,&header,&issue),VIREO_OK);
    EXPECT(vireo_protocol_response_header_validate(&header,&issue),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_verify(actual,32,NULL,0,&issue),VIREO_OK);
    release_peer(&p);
}

/** 真实SSL写WANT跨connection enqueue；原请求稳定且最终字节精确。 */
static void retry_contract(void)
{
    peer_t p=make_peer(); handshake(&p); configure(&p,512,131072);
    int small=4096; CHECK(setsockopt(p.server_fd,SOL_SOCKET,SO_SNDBUF,&small,sizeof(small))==0);
    uint8_t *source=malloc(80001), *actual=malloc(80001); CHECK(source!=NULL && actual!=NULL);
    for(size_t i=0;i<80001;++i) { source[i]=(uint8_t)(i%251); }
    EXPECT(vireo_connection_write_enqueue(p.connection,source,80000,NULL),VIREO_OK);
    vireo_tls_io_budget_t budget={16384,1}; vireo_tls_io_progress_t report;
    bool wanted=false; size_t calls=0;
    for(size_t i=0;i<32;++i) {
        EXPECT(vireo_tls_connection_send(p.tls,&budget,&report,NULL),VIREO_OK);
        calls+=report.native_calls;
        if(report.stop_reason==VIREO_TLS_IO_STOP_WOULD_BLOCK) { wanted=true; break; }
    }
    CHECK(wanted && io_info(&p).write_retry_bytes>0);
    EXPECT(vireo_connection_write_enqueue(p.connection,source+80000,1,NULL),VIREO_OK);
    vireo_tls_io_budget_t tiny={1,1};
    EXPECT(vireo_tls_connection_send(p.tls,&tiny,&report,NULL),VIREO_RESULT_RANGE);
    size_t received=0;
    for(size_t i=0;i<4096 && received<80001;++i) {
        EXPECT(vireo_tls_connection_send(p.tls,&budget,&report,NULL),VIREO_OK);
        received+=client_read(&p,actual+received,80001-received);
    }
    CHECK(received==80001 && memcmp(actual,source,80001)==0 && io_info(&p).write_size==0);
    printf("real write WANT; initial native calls=%zu; exact bytes=%zu\n",calls,received);
    free(source);free(actual);release_peer(&p);
}

/** 尾部完整帧在TLS关闭COMPLETE后仍通过原connection解析/消费。 */
static void close_contract(void)
{
    peer_t p=make_peer(); handshake(&p); configure(&p,512,512);
    vireo_monotonic_ns_t now=now_ns();
    EXPECT(vireo_tls_connection_close_request(p.tls,now,now+UINT64_C(5000000000),NULL),VIREO_OK);
    vireo_tls_close_progress_t report;
    EXPECT(vireo_tls_connection_close_step_at(p.tls,now_ns(),512,&report,NULL),VIREO_OK);
    CHECK(report.info.local_notify_sent);
    uint8_t request[32];make_frame(request,7,false);client_write(&p,request,32);
    ERR_clear_error(); int returned=SSL_shutdown(p.client);CHECK(returned==0 || returned==1);
    bool complete=false;
    for(size_t i=0;i<128;++i) {
        EXPECT(vireo_tls_connection_close_step_at(p.tls,now_ns(),512,&report,NULL),VIREO_OK);
        if(report.info.state==VIREO_TLS_CLOSE_COMPLETE){complete=true;break;}
    }
    CHECK(complete && connection_info(&p).read_eof && io_info(&p).read_size==32);
    vireo_connection_frame_view_t views[4];vireo_connection_frame_error_t error;
    vireo_connection_frame_info_t parsed=parse(&p,128,VIREO_OK,views,&error);
    CHECK(parsed.frame_count==1 && parsed.stop_reason==VIREO_CONNECTION_FRAME_STOP_EOF);
    EXPECT(vireo_connection_write_enqueue(p.connection,request,32,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_connection_read_consume(p.connection,32),VIREO_OK);release_peer(&p);
}

/** 满区先消费，库内余字节无新fd事件可续读；真实notify后的半帧必须报截断。 */
static void full_and_truncated(void)
{
    peer_t p=make_peer();handshake(&p);configure(&p,128,512);
    uint8_t bytes[136];
    for(uint32_t i=0;i<4;++i){make_frame(bytes+32*i,i+1,false);}
    memset(bytes+128,0xA5,8);client_write(&p,bytes,sizeof(bytes));receive_bytes(&p,128);
    vireo_tls_io_flow_t flow;
    EXPECT(vireo_tls_connection_flow_refresh(p.tls,&flow,NULL),VIREO_OK);
    CHECK(flow.read_pressure && !flow.application_read_enabled);
    vireo_tls_io_budget_t budget={512,8};vireo_tls_io_progress_t progress;
    EXPECT(vireo_tls_connection_receive(p.tls,&budget,&progress,NULL),VIREO_OK);
    CHECK(progress.bytes==0 && progress.native_calls==0);
    vireo_connection_frame_view_t views[4];vireo_connection_frame_error_t error;
    vireo_connection_frame_info_t parsed=parse(&p,128,VIREO_OK,views,&error);
    CHECK(parsed.frame_count==4);
    EXPECT(vireo_connection_read_consume(p.connection,128),VIREO_OK);
    EXPECT(vireo_tls_connection_flow_refresh(p.tls,&flow,NULL),VIREO_OK);
    CHECK(!flow.read_pressure && flow.resume_read);receive_bytes(&p,8);
    ERR_clear_error();CHECK(SSL_shutdown(p.client)==0);
    EXPECT(vireo_tls_connection_receive(p.tls,&budget,&progress,NULL),VIREO_OK);
    CHECK(progress.stop_reason==VIREO_TLS_IO_STOP_PEER_EOF && connection_info(&p).read_eof);
    parsed=parse(&p,128,VIREO_RESULT_PROTOCOL,views,&error);
    CHECK(parsed.frame_count==0 && error.issue==VIREO_CONNECTION_FRAME_ISSUE_TRUNCATED);
    CHECK(connection_info(&p).read_buffer.readable_size==8);
    vireo_monotonic_ns_t now=now_ns();
    EXPECT(vireo_tls_connection_close_request(p.tls,now,now+UINT64_C(5000000000),NULL),VIREO_OK);
    vireo_tls_close_progress_t close_report;
    EXPECT(vireo_tls_connection_close_step_at(p.tls,now_ns(),512,&close_report,NULL),VIREO_OK);
    CHECK(close_report.info.state==VIREO_TLS_CLOSE_COMPLETE);
    EXPECT(vireo_connection_read_consume(p.connection,8),VIREO_OK);release_peer(&p);
}

static void timeout_and_fatal(void)
{
    peer_t p=make_peer();handshake(&p);configure(&p,512,512);
    uint8_t data[32]={0};
    EXPECT(vireo_tls_connection_close_request(p.tls,10,10,NULL),VIREO_OK);
    vireo_tls_close_progress_t report;
    EXPECT(vireo_tls_connection_close_step_at(p.tls,10,512,&report,NULL),VIREO_RESULT_TIMEOUT);
    vireo_connection_error_t error;
    EXPECT(vireo_connection_write_enqueue(p.connection,data,32,&error),VIREO_RESULT_TIMEOUT);
    CHECK(error.stage==VIREO_CONNECTION_STAGE_TLS && error.tls_error.stage==VIREO_TLS_CONNECTION_STAGE_CLOSE_DEADLINE);
    CHECK(error.system_errno==0 && error.tls_error.openssl_error_code==0);
    release_peer(&p);
    p=make_peer();handshake(&p);configure(&p,512,512);
    CHECK(shutdown(p.client_fd,SHUT_WR)==0);
    vireo_tls_io_budget_t budget={512,8};vireo_tls_io_progress_t progress;vireo_tls_connection_error_t original;
    EXPECT(vireo_tls_connection_receive(p.tls,&budget,&progress,&original),VIREO_RESULT_PROTOCOL);
    EXPECT(vireo_connection_write_enqueue(p.connection,data,32,&error),VIREO_RESULT_PROTOCOL);
    CHECK(error.tls_error.stage==original.stage && error.tls_error.openssl_error_code==original.openssl_error_code);
    CHECK(!connection_info(&p).read_eof);
    release_peer(&p);
}

int main(void)
{
    CHECK(setvbuf(stdout,NULL,_IONBF,0)==0);
    size_t before=fd_count(); struct sigaction old,ignore={0};
    ignore.sa_handler=SIG_IGN;CHECK(sigemptyset(&ignore.sa_mask)==0);
    CHECK(sigaction(SIGPIPE,&ignore,&old)==0);
    resource_contract();puts("PASS resources/rollback/single-close/reused-fd");
    borrow_raw();puts("PASS raw borrow/output preservation");
    disabled_contract();puts("PASS disabled snapshots and raw mode gates");
    binding_contract();puts("PASS real loop and callback lifetime");
    framing_contract();puts("PASS real TLS fragments/coalescing/CRC/shared views and consume");
    response_contract();puts("PASS shared response FIFO/full/tail-space/exact response");
    retry_contract();puts("PASS real write WANT plus connection enqueue");
    close_contract();puts("PASS real dual close with retained complete tail frame");
    full_and_truncated();puts("PASS full FIFO/consume/pending resume/EOF truncated frame");
    timeout_and_fatal();puts("PASS close timeout and native fatal diagnostics");
    CHECK(sigaction(SIGPIPE,&old,NULL)==0);size_t after=fd_count();CHECK(before==after);
    printf("10 groups passed; fd %zu -> %zu\n",before,after);return 0;
}
