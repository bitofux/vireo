/*
- PROJECT : VIREO
- FILE    : test_connection_pool_tls.c
- AUTHOR  : bitofux
- DATE    : 2026-10-17
- BRIEF   : TLS准备态入池、固定计费/owner/代际和真实握手帧闭环验证
 */
#define _GNU_SOURCE
#include "net/connection_pool_internal.h"
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

/** 客户端仅为可信TLS互操作测试，不属于产品client实现。 */
typedef struct peer {
    vireo_connection_t *connection; /**< 入池前为owner；入池后仅短借，清理须走pool release。 */
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
    if (p->client_fd >= 0) CHECK(close(p->client_fd) == 0);
}
static vireo_monotonic_ns_t now_ns(void)
{
    vireo_monotonic_ns_t now;
    EXPECT(vireo_clock_monotonic_now(&now, NULL), VIREO_OK); return now;
}
static void handshake(peer_t *p)
{
    vireo_monotonic_ns_t now = now_ns();
    vireo_tls_handshake_deadline_info_t deadline;
    EXPECT(vireo_tls_connection_handshake_deadline_inspect(p->tls,&deadline,NULL),VIREO_OK);
    if (!deadline.armed) {
        EXPECT(vireo_tls_connection_handshake_deadline_arm(p->tls, now, now+UINT64_C(5000000000), NULL), VIREO_OK);
    }
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

static void prepare(peer_t *p, size_t read_capacity, size_t write_capacity)
{
    vireo_tls_io_options_t options = {read_capacity,write_capacity,read_capacity+write_capacity+32768,
        128,127,read_capacity,0,write_capacity};
    EXPECT(vireo_tls_connection_io_prepare(p->tls,&options,NULL),VIREO_OK);
}
static vireo_connection_pool_t *make_pool(size_t capacity, size_t bytes)
{
    vireo_connection_pool_t *pool = NULL;
    vireo_connection_pool_options_t opts = {capacity,65536,bytes};
    EXPECT(vireo_connection_pool_create(&opts,&pool,NULL),VIREO_OK); return pool;
}
static vireo_connection_pool_info_t pool_info(vireo_connection_pool_t *pool)
{
    vireo_connection_pool_info_t info;
    EXPECT(vireo_connection_pool_inspect(pool,&info),VIREO_OK); return info;
}
static vireo_connection_pool_lease_t adopt(vireo_connection_pool_t *pool, peer_t *p)
{
    vireo_connection_pool_lease_t lease = {0}; p->tls = NULL;
    EXPECT(vireo_connection_pool_adopt(pool,&p->connection,&lease,NULL),VIREO_OK);
    CHECK(p->connection == NULL && lease.pool_id != 0 && lease.generation != 0);
    EXPECT(vireo_connection_pool_lookup(pool,lease,&p->connection),VIREO_OK);
    EXPECT(vireo_connection_tls_borrow(p->connection,&p->tls),VIREO_OK); return lease;
}
static void release_adopted(vireo_connection_pool_t *pool, vireo_connection_pool_lease_t *lease, peer_t *p)
{
    p->connection = NULL; p->tls = NULL;
    EXPECT(vireo_connection_pool_release(pool,lease,NULL),VIREO_OK);
    CHECK(lease->pool_id == 0 && lease->slot_index == 0 && lease->generation == 0);
    CHECK(fcntl(p->server_fd,F_GETFD) == -1 && errno == EBADF);
    SSL_free(p->client); p->client = NULL;
    if (p->client_fd >= 0) CHECK(close(p->client_fd) == 0);
}
static void reject(vireo_connection_pool_t *pool, peer_t *p, vireo_result_t result)
{
    vireo_connection_t *original = p->connection;
    vireo_connection_pool_lease_t lease = {77,88,99}, saved = lease;
    vireo_connection_pool_info_t before = pool_info(pool);
    vireo_connection_pool_operation_error_t error;
    EXPECT(vireo_connection_pool_adopt(pool,&p->connection,&lease,&error),result);
    CHECK(p->connection == original && lease.pool_id == saved.pool_id &&
        lease.slot_index == saved.slot_index && lease.generation == saved.generation);
    vireo_connection_pool_info_t after = pool_info(pool);
    CHECK(before.leased_slots == after.leased_slots && before.buffer_capacity_bytes == after.buffer_capacity_bytes);
    CHECK(fcntl(p->server_fd,F_GETFD) >= 0);
}

/** 真实资源已计费，准备态仍不能透过业务层使用这些字节。 */
static void prepared_contract(void)
{
    peer_t p = make_peer(); vireo_connection_pool_t *pool = make_pool(1,256);
    reject(pool,&p,VIREO_RESULT_BUSY); prepare(&p,128,128);
    vireo_connection_info_t info = connection_info(&p); vireo_tls_io_info_t io = io_info(&p);
    CHECK(info.transport == VIREO_CONNECTION_TRANSPORT_TLS && info.buffer_capacity_bytes == 256);
    CHECK(info.max_buffer_bytes == 256 && !info.read_eof && io.buffer_bytes == 33024);
    CHECK(info.read_buffer.capacity == 128 && info.read_buffer.tail_space == 128);
    CHECK(info.write_buffer.capacity == 128 && info.write_buffer.tail_space == 128);
    CHECK(io.state == VIREO_TLS_IO_PREPARED && !info.flow_enabled);
    uint8_t const *view = (uint8_t const *)&io; size_t size = 999;
    EXPECT(vireo_connection_read_peek(p.connection,&view,&size),VIREO_RESULT_BUSY);
    CHECK(view == (uint8_t const *)&io && size == 999);
    EXPECT(vireo_connection_read_consume(p.connection,0),VIREO_RESULT_BUSY);
    EXPECT(vireo_connection_write_enqueue(p.connection,NULL,0,NULL),VIREO_RESULT_BUSY);
    vireo_connection_frame_options_t opts = {VIREO_CONNECTION_FRAME_REQUEST,128};
    vireo_connection_frame_budget_t budget = {4,512};
    vireo_connection_frame_view_t frames[4]; memset(frames,0xA1,sizeof(frames));
    vireo_connection_frame_info_t report; memset(&report,0xA2,sizeof(report));
    unsigned char saved[sizeof(report)], saved_frames[sizeof(frames)];
    memcpy(saved,&report,sizeof(saved)); memcpy(saved_frames,frames,sizeof(saved_frames));
    EXPECT(vireo_connection_frames_peek(p.connection,&opts,&budget,frames,4,&report,NULL),VIREO_RESULT_BUSY);
    CHECK(memcmp(saved,&report,sizeof(saved)) == 0 && memcmp(saved_frames,frames,sizeof(saved_frames)) == 0);
    vireo_connection_pool_lease_t lease = adopt(pool,&p), old = lease;
    CHECK(pool_info(pool).buffer_capacity_bytes == 256 && pool_info(pool).leased_slots == 1);
    EXPECT(vireo_connection_pool_destroy(&pool,NULL),VIREO_RESULT_BUSY);
    release_adopted(pool,&lease,&p);
    vireo_connection_t *out = NULL;
    EXPECT(vireo_connection_pool_lookup(pool,old,&out),VIREO_RESULT_NOT_FOUND);
    CHECK(pool_info(pool).buffer_capacity_bytes == 0 && pool_info(pool).available_slots == 1);
    p = make_peer(); prepare(&p,128,128); lease = adopt(pool,&p);
    CHECK(lease.pool_id == old.pool_id && lease.slot_index == old.slot_index && lease.generation != old.generation);
    EXPECT(vireo_connection_pool_lookup(pool,old,&out),VIREO_RESULT_NOT_FOUND);
    release_adopted(pool,&lease,&p); EXPECT(vireo_connection_pool_destroy(&pool,NULL),VIREO_OK);
}

static void budgets(void)
{
    for (unsigned int mode = 0; mode < 4; ++mode) {
        size_t capacity = mode == 2 ? 1 : 2;
        size_t bytes = mode == 0 ? 255 : (mode == 1 ? 256 : 512);
        vireo_connection_pool_t *pool = make_pool(capacity,bytes);
        peer_t first = make_peer(), second = make_peer(); prepare(&first,128,128); prepare(&second,128,128);
        if (mode == 0) {
            reject(pool,&first,VIREO_RESULT_RANGE); release_peer(&first); release_peer(&second);
        } else {
            vireo_connection_pool_lease_t one = adopt(pool,&first);
            if (mode != 3) { reject(pool,&second,VIREO_RESULT_BUSY); release_peer(&second); }
            else {
                vireo_connection_pool_lease_t two = adopt(pool,&second);
                CHECK(pool_info(pool).leased_slots == 2 && pool_info(pool).buffer_capacity_bytes == 512);
                release_adopted(pool,&two,&second);
            }
            release_adopted(pool,&one,&first);
        }
        CHECK(pool_info(pool).leased_slots == 0 && pool_info(pool).buffer_capacity_bytes == 0);
        EXPECT(vireo_connection_pool_destroy(&pool,NULL),VIREO_OK);
    }
}

/** 入池时尚无ClientHello，真实WANT不激活；成功后沿同租约收分段/粘帧并回精确响应。 */
static void real_framing(void)
{
    peer_t p = make_peer(); prepare(&p,256,256);
    vireo_connection_pool_t *pool = make_pool(1,512); vireo_connection_pool_lease_t lease = adopt(pool,&p);
    vireo_monotonic_ns_t now = now_ns();
    EXPECT(vireo_tls_connection_handshake_deadline_arm(p.tls,now,now+UINT64_C(5000000000),NULL),VIREO_OK);
    vireo_tls_handshake_info_t step;
    EXPECT(vireo_tls_connection_handshake_step_at(p.tls,now_ns(),&step,NULL),VIREO_OK);
    CHECK(step.wait == VIREO_TLS_HANDSHAKE_WAIT_READ && io_info(&p).state == VIREO_TLS_IO_PREPARED);
    vireo_connection_pool_lease_t same = lease;
    handshake(&p); CHECK(io_info(&p).state == VIREO_TLS_IO_OPEN);
    vireo_connection_t *current = NULL;
    EXPECT(vireo_connection_pool_lookup(pool,same,&current),VIREO_OK); CHECK(current == p.connection);
    CHECK(pool_info(pool).buffer_capacity_bytes == 512);
    uint8_t requests[96], responses[96], received[96];
    for (size_t i = 0; i < 3; ++i) { make_frame(requests+i*32,(uint32_t)i+1,false); make_frame(responses+i*32,(uint32_t)i+1,true); }
    client_write(&p,requests,13); receive_bytes(&p,13);
    vireo_connection_frame_view_t views[4]; vireo_connection_frame_error_t error;
    CHECK(parse(&p,128,VIREO_OK,views,&error).frame_count == 0);
    client_write(&p,requests+13,83); receive_bytes(&p,83);
    CHECK(parse(&p,128,VIREO_OK,views,&error).frame_count == 3);
    for (size_t i = 0; i < 3; ++i) CHECK(views[i].header.sequence == (uint32_t)i+1);
    EXPECT(vireo_connection_read_consume(p.connection,96),VIREO_OK);
    EXPECT(vireo_connection_write_enqueue(p.connection,responses,96,NULL),VIREO_OK);
    vireo_tls_io_budget_t allowance = {32,1}; vireo_tls_io_progress_t progress;
    for (size_t i = 0; i < 3; ++i) {
        EXPECT(vireo_tls_connection_send(p.tls,&allowance,&progress,NULL),VIREO_OK); CHECK(progress.bytes == 32);
    }
    size_t total = 0;
    for (size_t round = 0; total < sizeof(received) && round < 128; ++round)
        total += client_read(&p,received+total,sizeof(received)-total);
    CHECK(total == sizeof(received) && memcmp(received,responses,sizeof(received)) == 0);
    CHECK(io_info(&p).write_size == 0 && pool_info(pool).buffer_capacity_bytes == 512);
    release_adopted(pool,&lease,&p); EXPECT(vireo_connection_pool_destroy(&pool,NULL),VIREO_OK);
}

static void timeout_and_fatal(void)
{
    for (unsigned int mode = 0; mode < 2; ++mode) {
        peer_t p = make_peer(); prepare(&p,128,128);
        vireo_connection_pool_t *pool = make_pool(1,256);
        EXPECT(vireo_tls_connection_handshake_deadline_arm(p.tls,100,200,NULL),VIREO_OK);
        vireo_connection_pool_lease_t lease = adopt(pool,&p);
        vireo_tls_handshake_info_t step; vireo_tls_connection_error_t first, again;
        vireo_result_t result;
        if (mode == 0) {
            EXPECT(vireo_tls_connection_handshake_step_at(p.tls,200,&step,&first),VIREO_RESULT_TIMEOUT);
            CHECK(!step.native_called); result = VIREO_RESULT_TIMEOUT;
        } else {
            EXPECT(vireo_tls_connection_handshake_step_at(p.tls,100,&step,NULL),VIREO_OK);
            CHECK(step.wait == VIREO_TLS_HANDSHAKE_WAIT_READ);
            SSL_free(p.client); p.client = NULL; CHECK(close(p.client_fd) == 0); p.client_fd = -1;
            errno = ECHILD; result = vireo_tls_connection_handshake_step_at(p.tls,101,&step,&first);
            CHECK(errno == ECHILD && (result == VIREO_RESULT_PROTOCOL || result == VIREO_RESULT_IO));
        }
        EXPECT(vireo_tls_connection_handshake_step_at(p.tls,199,&step,&again),result);
        CHECK(!step.native_called && first.stage == again.stage && first.system_errno == again.system_errno &&
            first.openssl_error_code == again.openssl_error_code && first.has_more_errors == again.has_more_errors);
        CHECK(io_info(&p).state == VIREO_TLS_IO_PREPARED && pool_info(pool).buffer_capacity_bytes == 256);
        EXPECT(vireo_connection_write_enqueue(p.connection,NULL,0,NULL),VIREO_RESULT_BUSY);
        release_adopted(pool,&lease,&p); CHECK(pool_info(pool).buffer_capacity_bytes == 0);
        EXPECT(vireo_connection_pool_destroy(&pool,NULL),VIREO_OK);
    }
}

/** 不能只看原RAW close=OPEN；TLS失效/关闭必须拒绝，旧握手后配置仍可入池。 */
static void tls_rejections_and_old_path(void)
{
    vireo_connection_pool_t *pool = make_pool(1,256); peer_t p = make_peer();
    prepare(&p,128,128);
    EXPECT(vireo_tls_connection_handshake_deadline_arm(p.tls,100,200,NULL),VIREO_OK);
    vireo_tls_handshake_info_t report;
    EXPECT(vireo_tls_connection_handshake_step_at(p.tls,200,&report,NULL),VIREO_RESULT_TIMEOUT);
    reject(pool,&p,VIREO_RESULT_BUSY); release_peer(&p);
    p = make_peer(); handshake(&p); reject(pool,&p,VIREO_RESULT_BUSY);
    configure(&p,128,128);
    uint8_t response[32]; make_frame(response,9,true);
    EXPECT(vireo_connection_write_enqueue(p.connection,response,32,NULL),VIREO_OK);
    vireo_connection_pool_lease_t lease = adopt(pool,&p); CHECK(io_info(&p).write_size == 32);
    release_adopted(pool,&lease,&p);
    p = make_peer(); prepare(&p,128,128); handshake(&p);
    vireo_monotonic_ns_t now = now_ns();
    EXPECT(vireo_tls_connection_close_request(p.tls,now,now+UINT64_C(5000000000),NULL),VIREO_OK);
    CHECK(connection_info(&p).close_state == VIREO_CONNECTION_CLOSE_OPEN);
    reject(pool,&p,VIREO_RESULT_BUSY); release_peer(&p);
    p = make_peer(); prepare(&p,128,128); handshake(&p);
    SSL_free(p.client); p.client = NULL; CHECK(close(p.client_fd) == 0); p.client_fd = -1;
    vireo_tls_io_budget_t budget = {128,4}; vireo_tls_io_progress_t progress;
    errno = ECHILD; vireo_result_t result = vireo_tls_connection_receive(p.tls,&budget,&progress,NULL);
    CHECK(errno == ECHILD && (result == VIREO_RESULT_PROTOCOL || result == VIREO_RESULT_IO));
    CHECK(io_info(&p).state == VIREO_TLS_IO_FAILED); reject(pool,&p,VIREO_RESULT_BUSY); release_peer(&p);
    EXPECT(vireo_connection_pool_destroy(&pool,NULL),VIREO_OK);
}

typedef struct callback_context {
    vireo_connection_pool_t *pool;
    vireo_connection_pool_lease_t lease;
    bool called;
} callback_context_t;

static void on_ready(vireo_connection_t *connection, uint32_t events, void *context)
{
    callback_context_t *c = context; CHECK(events != 0); c->called = true;
    EXPECT(vireo_connection_detach(connection,NULL),VIREO_OK);
    EXPECT(vireo_connection_pool_release(c->pool,&c->lease,NULL),VIREO_RESULT_BUSY);
    CHECK(c->lease.pool_id != 0 && pool_info(c->pool).leased_slots == 1);
}
static void binding_and_callback(void)
{
    peer_t p = make_peer(); prepare(&p,128,128); vireo_connection_pool_t *pool = make_pool(1,256);
    vireo_event_loop_t *loop = NULL; vireo_event_loop_options_t opts = {4,65536,4};
    EXPECT(vireo_event_loop_create(&opts,&loop,NULL),VIREO_OK);
    callback_context_t context = {.pool=pool};
    EXPECT(vireo_connection_attach(p.connection,loop,VIREO_EPOLL_INTEREST_WRITE,on_ready,&context,NULL),VIREO_OK);
    reject(pool,&p,VIREO_RESULT_BUSY);
    EXPECT(vireo_connection_detach(p.connection,NULL),VIREO_OK);
    context.lease = adopt(pool,&p);
    EXPECT(vireo_connection_attach(p.connection,loop,VIREO_EPOLL_INTEREST_WRITE,on_ready,&context,NULL),VIREO_OK);
    EXPECT(vireo_connection_pool_release(pool,&context.lease,NULL),VIREO_RESULT_BUSY);
    vireo_event_loop_run_info_t run;
    EXPECT(vireo_event_loop_run_once(loop,0,&run,NULL),VIREO_OK); CHECK(context.called);
    CHECK(!connection_info(&p).loop_attached && pool_info(pool).buffer_capacity_bytes == 256);
    release_adopted(pool,&context.lease,&p);
    EXPECT(vireo_event_loop_destroy(&loop,NULL),VIREO_OK); EXPECT(vireo_connection_pool_destroy(&pool,NULL),VIREO_OK);
}

/** 本pool own缝只污染自己的公开依赖快照/消费结果，不访问其他模块private。 */
typedef struct pool_fault { unsigned int mode; int replacement; } pool_fault_t;
static vireo_result_t observed(void *context, vireo_connection_t const *connection, vireo_connection_info_t *out)
{
    pool_fault_t *fault = context; vireo_result_t result = vireo_connection_inspect(connection,out);
    if (result == VIREO_OK && fault->mode == 1) out->transport = (vireo_connection_transport_t)99;
    if (result == VIREO_OK && fault->mode == 2) ++out->buffer_capacity_bytes;
    return result;
}
static vireo_result_t destroyed(void *context, vireo_connection_t **owner, vireo_connection_error_t *error)
{
    pool_fault_t *fault = context; vireo_result_t result = vireo_connection_destroy(owner,error);
    if (result == VIREO_OK && fault->mode == 3) {
        fault->replacement = open("/dev/null",O_RDONLY|O_CLOEXEC); CHECK(fault->replacement >= 0);
        if (error != NULL) *error = (vireo_connection_error_t){.stage=VIREO_CONNECTION_STAGE_CLOSE_SOCKET,.system_errno=EINTR};
        return VIREO_RESULT_IO; /* own消费型错误报告，不冒充真实close返回EINTR。 */
    }
    return result;
}
static void own_snapshots_and_consumption(void)
{
    pool_fault_t fault = {0}; vireo_connection_pool_connection_ops_t ops = {&fault,observed,destroyed};
    vireo_connection_pool_t *pool = NULL; vireo_connection_pool_options_t options = {1,65536,256};
    EXPECT(vireo_connection_pool_create_with_connection_ops(&options,&ops,&pool,NULL),VIREO_OK);
    peer_t p = make_peer(); prepare(&p,128,128);
    fault.mode = 1; reject(pool,&p,VIREO_RESULT_INTERNAL);
    fault.mode = 2; reject(pool,&p,VIREO_RESULT_INTERNAL);
    fault.mode = 0; vireo_connection_pool_lease_t lease = adopt(pool,&p), old = lease;
    p.connection = NULL; p.tls = NULL; fault.mode = 3; vireo_connection_pool_operation_error_t error;
    EXPECT(vireo_connection_pool_release(pool,&lease,&error),VIREO_RESULT_IO);
    CHECK(lease.pool_id == 0 && pool_info(pool).buffer_capacity_bytes == 0);
    CHECK(error.stage == VIREO_CONNECTION_POOL_OPERATION_DESTROY_CONNECTION &&
        error.connection_error.system_errno == EINTR && fcntl(fault.replacement,F_GETFD) >= 0);
    vireo_connection_t *borrowed = NULL;
    EXPECT(vireo_connection_pool_lookup(pool,old,&borrowed),VIREO_RESULT_NOT_FOUND);
    CHECK(close(fault.replacement) == 0); SSL_free(p.client); CHECK(close(p.client_fd) == 0);
    EXPECT(vireo_connection_pool_destroy(&pool,NULL),VIREO_OK);
}

static void raw_compatibility(void)
{
    int pair[2]; CHECK(socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair) == 0);
    vireo_connection_t *owner = NULL; vireo_connection_options_t opts = {128,128,256};
    EXPECT(vireo_connection_create(&opts,&pair[0],&owner,NULL),VIREO_OK);
    vireo_connection_pool_t *pool = make_pool(1,256); vireo_connection_pool_lease_t lease = {0};
    ERR_raise(ERR_LIB_USER,902); unsigned long previous = ERR_peek_error();
    EXPECT(vireo_connection_pool_adopt(pool,&owner,&lease,NULL),VIREO_OK);
    CHECK(owner == NULL && ERR_peek_error() == previous); ERR_clear_error();
    EXPECT(vireo_connection_pool_release(pool,&lease,NULL),VIREO_OK);
    CHECK(close(pair[1]) == 0); EXPECT(vireo_connection_pool_destroy(&pool,NULL),VIREO_OK);
}

int main(void)
{
    size_t before = fd_count(); struct sigaction old, ignored = {0};
    ignored.sa_handler = SIG_IGN; CHECK(sigemptyset(&ignored.sa_mask) == 0);
    CHECK(sigaction(SIGPIPE,&ignored,&old) == 0);
    prepared_contract(); budgets(); real_framing(); timeout_and_fatal();
    tls_rejections_and_old_path(); binding_and_callback(); own_snapshots_and_consumption(); raw_compatibility();
    CHECK(sigaction(SIGPIPE,&old,NULL) == 0); size_t after = fd_count(); CHECK(before == after);
    printf("TLS pool: 8 groups passed; fd %zu -> %zu; trusted TLS1.3/3 frames/96 exact response bytes\n",before,after);
    return 0;
}

