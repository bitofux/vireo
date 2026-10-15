/*
 * PROJECT : VIREO
 * FILE    : test_inflight_foundation.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 真实客户身份、复用代次、关闭分层与完整失败保持
 */
#define _GNU_SOURCE
#include <vireo/net/inflight.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); return false; \
} } while (0)

/** 测试独占的真实 loopback 资源；只通过公开合同访问。 */
typedef struct fixture {
    vireo_tcp_server_t *server;           /**< 本客户及 listener 的资源根。 */
    vireo_tcp_server_t *other_server;     /**< 独立拥有域，用于跨域拒绝。 */
    vireo_connection_pool_lease_t client; /**< 当前客户值，归还后清零。 */
    int peer;                            /**< caller 的 TCP 对端，-1 为空。 */
    int listener_fd;                     /**< 构造期间 owner fd，转移后 -1。 */
    vireo_acceptor_t *listener;           /**< 构造期 owner，收纳后 NULL。 */
    struct sockaddr_in address;          /**< loopback 数值端点，供重接客户。 */
} fixture_t;

static bool add_client(fixture_t *f) {
    CHECK(f->peer == -1 && f->client.pool_id == 0);
    f->peer = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(f->peer >= 0);
    CHECK(connect(f->peer, (struct sockaddr const *)&f->address, sizeof f->address) == 0);
    vireo_connection_options_t const options = {64, 64, 128};
    vireo_tcp_server_admit_budget_t const budget = {1, 1};
    vireo_tcp_server_admit_info_t info;
    CHECK(vireo_tcp_server_admit_batch(f->server, &options, &budget, &f->client, 1,
                                       &info, NULL) == VIREO_OK);
    CHECK(info.admitted_count == 1 && info.accepted_count == 1);
    return true;
}

static bool setup(fixture_t *f) {
    *f = (fixture_t){.peer = -1, .listener_fd = -1};
    vireo_tcp_server_options_t const options = {1, 2, VIREO_TCP_SERVER_MAX_MEMORY, 128};
    CHECK(vireo_tcp_server_create(&options, &f->server, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_create(&options, &f->other_server, NULL) == VIREO_OK);
    f->listener_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(f->listener_fd >= 0);
    f->address.sin_family = AF_INET;
    f->address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(f->listener_fd, (struct sockaddr const *)&f->address, sizeof f->address) == 0);
    CHECK(listen(f->listener_fd, 4) == 0);
    socklen_t length = sizeof f->address;
    CHECK(getsockname(f->listener_fd, (struct sockaddr *)&f->address, &length) == 0);
    CHECK(length == sizeof f->address);
    vireo_acceptor_options_t const listener_options = {VIREO_ACCEPTOR_MAX_MEMORY};
    CHECK(vireo_acceptor_create(&listener_options, &f->listener_fd, &f->listener, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_adopt_listener(f->server, &f->listener, NULL) == VIREO_OK);
    return add_client(f);
}

static bool release_client(fixture_t *f) {
    CHECK(vireo_tcp_server_release_client(f->server, &f->client, NULL) == VIREO_OK);
    CHECK(f->client.pool_id == 0 && f->client.slot_index == 0 && f->client.generation == 0);
    CHECK(close(f->peer) == 0);
    f->peer = -1;
    return true;
}

static bool cleanup(fixture_t *f) {
    if (f->client.pool_id != 0) CHECK(release_client(f));
    if (f->peer >= 0) CHECK(close(f->peer) == 0);
    if (f->listener_fd >= 0) CHECK(close(f->listener_fd) == 0);
    CHECK(vireo_acceptor_destroy(&f->listener, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_destroy(&f->server, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_destroy(&f->other_server, NULL) == VIREO_OK);
    CHECK(f->server == NULL && f->other_server == NULL);
    return true;
}

static bool make(fixture_t *f, uint64_t instance, uint64_t deadline,
                  vireo_task_metadata_t *out) {
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_CHECK_CLIENT;
    errno = EDOM;
    CHECK(vireo_inflight_metadata_make(f->server, f->client, 7, instance, 9, deadline,
                                        out, &stage) == VIREO_OK);
    CHECK(errno == EDOM && stage == VIREO_INFLIGHT_NONE);
    return true;
}

static bool check_state(fixture_t *f, vireo_task_metadata_t metadata,
                         vireo_connection_close_state_t expected) {
    vireo_connection_close_state_t out = VIREO_CONNECTION_CLOSE_READY;
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_CHECK_METADATA;
    errno = ERANGE;
    CHECK(vireo_inflight_check_client(f->server, metadata, &out, &stage) == VIREO_OK);
    CHECK(errno == ERANGE && stage == VIREO_INFLIGHT_NONE && out == expected);
    out = VIREO_CONNECTION_CLOSE_READY;
    errno = EDOM;
    CHECK(vireo_inflight_check_client(f->server, metadata, &out, NULL) == VIREO_OK);
    CHECK(errno == EDOM && out == expected);
    return true;
}

/** 失败只比较未发布输出的全部字节；成功字段单独比较，不依赖 padding。 */
static bool make_fails(vireo_tcp_server_t const *server, vireo_connection_pool_lease_t client,
    uint32_t sequence, uint64_t instance, uint32_t operation, vireo_result_t expected,
    vireo_inflight_stage_t expected_stage) {
    vireo_task_metadata_t out;
    unsigned char before[sizeof out];
    memset(&out, 0xa5, sizeof out);
    memcpy(before, &out, sizeof out);
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_MAKE_ROUTE;
    errno = EDOM;
    CHECK(vireo_inflight_metadata_make(server, client, sequence, instance, operation,
                                        UINT64_MAX, &out, &stage) == expected);
    CHECK(errno == EDOM && stage == expected_stage && memcmp(before, &out, sizeof out) == 0);
    errno = ERANGE;
    CHECK(vireo_inflight_metadata_make(server, client, sequence, instance, operation,
                                        UINT64_MAX, &out, NULL) == expected);
    CHECK(errno == ERANGE && memcmp(before, &out, sizeof out) == 0);
    return true;
}

static bool check_fails(vireo_tcp_server_t const *server, vireo_task_metadata_t metadata,
    vireo_result_t expected, vireo_inflight_stage_t expected_stage) {
    vireo_connection_close_state_t out = VIREO_CONNECTION_CLOSE_DRAINING;
    unsigned char before[sizeof out];
    memcpy(before, &out, sizeof out);
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_MAKE_METADATA;
    errno = EDOM;
    CHECK(vireo_inflight_check_client(server, metadata, &out, &stage) == expected);
    CHECK(errno == EDOM && stage == expected_stage && memcmp(before, &out, sizeof out) == 0);
    errno = ERANGE;
    CHECK(vireo_inflight_check_client(server, metadata, &out, NULL) == expected);
    CHECK(errno == ERANGE && memcmp(before, &out, sizeof out) == 0);
    return true;
}

static bool valid_mapping(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_task_metadata_t out;
    memset(&out, 0xa5, sizeof out);
    CHECK(make(&f, 400, 1000000000, &out));
    CHECK(out.route.client_owner_id == f.client.pool_id);
    CHECK(out.route.client_slot_index == f.client.slot_index && f.client.slot_index == 0);
    CHECK(out.route.client_generation == f.client.generation && out.route.request_sequence == 7);
    CHECK(out.request_instance_id == 400 && out.operation == 9 && out.deadline_ns == 1000000000);
    CHECK(check_state(&f, out, VIREO_CONNECTION_CLOSE_OPEN));
    return cleanup(&f);
}

static bool numeric_boundaries(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_task_metadata_t out;
    errno = EDOM;
    CHECK(vireo_inflight_metadata_make(f.server, f.client, UINT32_MAX, UINT64_MAX,
                                        UINT32_MAX, 0, &out, NULL) == VIREO_OK);
    CHECK(errno == EDOM && out.route.request_sequence == UINT32_MAX);
    CHECK(out.request_instance_id == UINT64_MAX && out.operation == UINT32_MAX && out.deadline_ns == 0);
    CHECK(check_state(&f, out, VIREO_CONNECTION_CLOSE_OPEN));
    CHECK(make(&f, 401, UINT64_MAX, &out));
    CHECK(out.deadline_ns == UINT64_MAX);
    CHECK(check_state(&f, out, VIREO_CONNECTION_CLOSE_OPEN));
    return cleanup(&f);
}

static bool make_basic_errors(void) {
    fixture_t f;
    CHECK(setup(&f));
    CHECK(make_fails(NULL, f.client, 7, 1, 9, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE));
    CHECK(make_fails(f.server, f.client, 0, 1, 9, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE));
    CHECK(make_fails(f.server, f.client, 7, 0, 9, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE));
    CHECK(make_fails(f.server, f.client, 7, 1, 0, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE));
    CHECK(make_fails(f.server, (vireo_connection_pool_lease_t){0}, 0, 1, 9,
                       VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE));
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_CHECK_CLIENT;
    errno = EDOM;
    CHECK(vireo_inflight_metadata_make(f.server, f.client, 7, 1, 9, 0, NULL,
                                        &stage) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM && stage == VIREO_INFLIGHT_NONE);
    return cleanup(&f);
}

static bool make_identity_errors(void) {
    fixture_t f;
    CHECK(setup(&f));
    CHECK(make_fails(f.server, (vireo_connection_pool_lease_t){0}, 7, 1, 9,
                       VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_CLIENT));
    vireo_connection_pool_lease_t bad = f.client;
    bad.pool_id = 0;
    CHECK(make_fails(f.server, bad, 7, 1, 9, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE));
    bad = f.client; bad.generation = 0;
    CHECK(make_fails(f.server, bad, 7, 1, 9, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE));
    CHECK(make_fails(f.other_server, f.client, 7, 1, 9,
                       VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_CHECK_CLIENT));
    bad = f.client; bad.slot_index = SIZE_MAX;
    CHECK(make_fails(f.server, bad, 7, 1, 9, VIREO_RESULT_RANGE, VIREO_INFLIGHT_CHECK_CLIENT));
    bad = f.client; bad.generation = UINT64_MAX;
    CHECK(bad.generation != f.client.generation);
    CHECK(make_fails(f.server, bad, 7, 1, 9, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_CLIENT));
    return cleanup(&f);
}

static bool check_shape_errors(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_task_metadata_t valid;
    CHECK(make(&f, 1, 0, &valid));
    CHECK(check_fails(NULL, valid, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE));
    CHECK(check_fails(f.server, (vireo_task_metadata_t){0}, VIREO_RESULT_INVALID_ARGUMENT,
                        VIREO_INFLIGHT_CHECK_METADATA));
    vireo_task_metadata_t bad = valid;
    bad.route.client_owner_id = 0;
    CHECK(check_fails(f.server, bad, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_CHECK_METADATA));
    bad = valid; bad.route.client_generation = 0;
    CHECK(check_fails(f.server, bad, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_CHECK_METADATA));
    bad = valid; bad.route.request_sequence = 0;
    CHECK(check_fails(f.server, bad, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_CHECK_METADATA));
    bad = valid; bad.request_instance_id = 0;
    CHECK(check_fails(f.server, bad, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_CHECK_METADATA));
    bad = valid; bad.operation = 0;
    CHECK(check_fails(f.server, bad, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_CHECK_METADATA));
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_CHECK_CLIENT;
    errno = EDOM;
    CHECK(vireo_inflight_check_client(f.server, bad, NULL, &stage) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM && stage == VIREO_INFLIGHT_NONE);
    return cleanup(&f);
}

static bool check_identity_errors(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_task_metadata_t valid;
    CHECK(make(&f, 1, 0, &valid));
    CHECK(check_fails(f.other_server, valid, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_CHECK_CLIENT));
    vireo_task_metadata_t bad = valid;
    bad.route.client_slot_index = SIZE_MAX;
    CHECK(check_fails(f.server, bad, VIREO_RESULT_RANGE, VIREO_INFLIGHT_CHECK_CLIENT));
    bad = valid; bad.route.client_generation = UINT64_MAX;
    CHECK(check_fails(f.server, bad, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_CLIENT));
    bad = valid; bad.operation = 0; bad.route.client_slot_index = SIZE_MAX;
    CHECK(check_fails(f.server, bad, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_CHECK_METADATA));
    return cleanup(&f);
}

static bool slot_reuse(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_task_metadata_t old;
    CHECK(make(&f, 1, UINT64_MAX, &old));
    vireo_connection_pool_lease_t const old_client = f.client;
    CHECK(release_client(&f));
    CHECK(check_fails(f.server, old, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_CLIENT));
    CHECK(make_fails(f.server, old_client, 7, 2, 9, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_CLIENT));
    CHECK(add_client(&f));
    CHECK(f.client.pool_id == old_client.pool_id && f.client.slot_index == old_client.slot_index);
    CHECK(f.client.generation != old_client.generation);
    CHECK(check_fails(f.server, old, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_CLIENT));
    CHECK(make_fails(f.server, old_client, 7, 2, 9, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_CLIENT));
    vireo_task_metadata_t current;
    CHECK(make(&f, 1, UINT64_MAX, &current));
    CHECK(check_state(&f, current, VIREO_CONNECTION_CLOSE_OPEN));
    bool same = true;
    CHECK(vireo_task_metadata_same_request(old, current, &same) == VIREO_OK && !same);
    return cleanup(&f);
}

static bool closing_clients(void) {
    fixture_t f;
    CHECK(setup(&f));
    uint8_t const byte = 0x5a;
    CHECK(vireo_tcp_server_client_write_enqueue(f.server, f.client, &byte, 1, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_client_request_close(f.server, f.client, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    vireo_task_metadata_t metadata;
    CHECK(make(&f, 1, 0, &metadata));
    CHECK(check_state(&f, metadata, VIREO_CONNECTION_CLOSE_DRAINING));
    CHECK(vireo_tcp_server_client_request_close(f.server, f.client, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    CHECK(make(&f, 2, UINT64_MAX, &metadata));
    CHECK(check_state(&f, metadata, VIREO_CONNECTION_CLOSE_READY));
    return cleanup(&f);
}

static bool stopped_server(void) {
    fixture_t f;
    CHECK(setup(&f));
    CHECK(vireo_tcp_server_request_stop(f.server, NULL) == VIREO_OK);
    vireo_tcp_server_info_t info;
    CHECK(vireo_tcp_server_inspect(f.server, &info) == VIREO_OK && info.stop_requested);
    vireo_task_metadata_t metadata;
    CHECK(make(&f, 1, 0, &metadata));
    CHECK(check_state(&f, metadata, VIREO_CONNECTION_CLOSE_OPEN));
    CHECK(vireo_tcp_server_client_request_close(f.server, f.client, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
        VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP, NULL) == VIREO_OK);
    CHECK(make(&f, 2, UINT64_MAX, &metadata));
    CHECK(check_state(&f, metadata, VIREO_CONNECTION_CLOSE_READY));
    return cleanup(&f);
}

/** 客户查询不能认证请求仍在途；不同请求均可查同一当前客户。 */
static bool request_and_resource_boundary(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_tcp_server_info_t before, after;
    vireo_tcp_server_client_info_t client_before, client_after;
    CHECK(vireo_tcp_server_inspect(f.server, &before) == VIREO_OK);
    CHECK(vireo_tcp_server_client_inspect(f.server, f.client, &client_before) == VIREO_OK);
    vireo_task_metadata_t a, b;
    CHECK(make(&f, 400, 0, &a));
    CHECK(make(&f, 401, UINT64_MAX, &b));
    bool same = true;
    CHECK(vireo_task_metadata_same_request(a, b, &same) == VIREO_OK && !same);
    CHECK(check_state(&f, a, VIREO_CONNECTION_CLOSE_OPEN));
    CHECK(check_state(&f, b, VIREO_CONNECTION_CLOSE_OPEN));
    b = a; b.operation = UINT32_MAX; b.deadline_ns = UINT64_MAX;
    CHECK(vireo_task_metadata_same_request(a, b, &same) == VIREO_OK && same);
    CHECK(check_state(&f, b, VIREO_CONNECTION_CLOSE_OPEN));
    CHECK(make_fails(f.other_server, f.client, 7, 402, 9,
                       VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_CHECK_CLIENT));
    CHECK(vireo_tcp_server_inspect(f.server, &after) == VIREO_OK);
    CHECK(vireo_tcp_server_client_inspect(f.server, f.client, &client_after) == VIREO_OK);
    CHECK(before.connection_count == after.connection_count && before.registered_connections == after.registered_connections);
    CHECK(before.available_connections == after.available_connections && before.pending_clients == after.pending_clients);
    CHECK(before.allocation_bytes == after.allocation_bytes && before.buffer_capacity_bytes == after.buffer_capacity_bytes);
    CHECK(client_before.queued == client_after.queued && client_before.pending_events == client_after.pending_events);
    CHECK(client_before.connection_info.close_state == client_after.connection_info.close_state);
    CHECK(client_before.connection_info.loop_interests == client_after.connection_info.loop_interests);
    CHECK(client_before.connection_info.read_buffer.readable_size == client_after.connection_info.read_buffer.readable_size);
    CHECK(client_before.connection_info.write_buffer.readable_size == client_after.connection_info.write_buffer.readable_size);
    return cleanup(&f);
}

/** 仅测试调度数据，不拥有模块资源。 */
typedef struct test_case {
    char const *name;       /**< 静态测试名称，只用于失败定位。 */
    bool (*run)(void);      /**< 同步组入口，完成自身公开资源清理。 */
} test_case_t;

int main(void) {
    test_case_t const cases[] = {
        {"valid_mapping", valid_mapping}, {"numeric_boundaries", numeric_boundaries},
        {"make_basic_errors", make_basic_errors}, {"make_identity_errors", make_identity_errors},
        {"check_shape_errors", check_shape_errors}, {"check_identity_errors", check_identity_errors},
        {"slot_reuse", slot_reuse}, {"closing_clients", closing_clients},
        {"stopped_server", stopped_server}, {"request_and_resource_boundary", request_and_resource_boundary}
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        if (!cases[i].run()) { fprintf(stderr, "FAIL %s\n", cases[i].name); return 1; }
        printf("PASS %s\n", cases[i].name);
    }
    printf("inflight foundation: %zu groups passed\n", sizeof cases / sizeof cases[0]);
    return 0;
}
