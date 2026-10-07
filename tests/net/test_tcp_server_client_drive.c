/*
- PROJECT : VIREO
- FILE    : test_tcp_server_client_drive.c
- AUTHOR  : bitofux
- DATE    : 2026-10-05
- BRIEF   : 此模块负责：
- -- 单客户有界组合、缓存续提示与主次失败
- -- 真实缓存/慢端、原诊断、整轮重入与关闭同步
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include "net/tcp_server_internal.h"

static unsigned failures, groups;
#define CHECK(c)                                                    \
    do {                                                            \
        if (!(c)) {                                                 \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); \
            ++failures;                                             \
        }                                                           \
    } while (0)
#define REQUIRE(c)                                                          \
    do {                                                                    \
        if (!(c)) {                                                         \
            fprintf(stderr, "fixture %s:%d: %s\n", __FILE__, __LINE__, #c); \
            exit(EXIT_FAILURE);                                             \
        }                                                                   \
    } while (0)
static vireo_tcp_server_options_t const server_options = {2, 2, 1048576, 16384};
static vireo_connection_options_t const connection_options = {256, 128, 384};
static vireo_connection_receive_budget_t const read_budget = {SIZE_MAX, 8};
static vireo_connection_send_budget_t const write_budget = {SIZE_MAX, 8};
static bool same(vireo_connection_pool_lease_t a, vireo_connection_pool_lease_t b) {
    return a.pool_id == b.pool_id && a.slot_index == b.slot_index && a.generation == b.generation;
}
static bool empty(vireo_connection_pool_lease_t l) {
    return l.pool_id == 0 && l.slot_index == 0 && l.generation == 0;
}
static unsigned fd_count(void) {
    DIR *d = opendir("/proc/self/fd");
    REQUIRE(d != NULL);
    unsigned n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
        if (e->d_name[0] != '.')
            ++n;
    REQUIRE(closedir(d) == 0);
    return n;
}
typedef struct fixture {
    vireo_tcp_server_t *server;
    vireo_connection_pool_lease_t clients[2];
    struct sockaddr_storage address;
    socklen_t length;
    int family, peers[2];
    bool release_busy;
    int raw_fds[2];
    vireo_connection_t *objects[2];
    unsigned created, policy_calls[6];
    int fault_operation;
    bool detach_io;
    bool receive_io, send_io, probe_on_sync;
    unsigned receive_calls, send_calls, frame_calls, inspect_calls, inspect_fail_at;
    vireo_acceptor_t *spare;
} fixture_t;
static void probe(fixture_t *f, bool processing);
static vireo_result_t accept_client(void *ctx, vireo_acceptor_t *a,
                                    vireo_acceptor_accept_budget_t const *b, int *fds, size_t n,
                                    vireo_acceptor_accept_info_t *i, vireo_acceptor_error_t *e) {
    (void)ctx;
    return vireo_acceptor_accept_batch(a, b, fds, n, i, e);
}
static vireo_result_t create_client(void *ctx, vireo_connection_options_t const *o, int *fd,
                                    vireo_connection_t **c, vireo_connection_error_t *e) {
    fixture_t *f = ctx;
    int const raw = *fd;
    vireo_result_t const r = vireo_connection_create(o, fd, c, e);
    if (r == VIREO_OK) {
        size_t const k = f->created++ % 2;
        f->raw_fds[k] = raw;
        f->objects[k] = *c;
    }
    return r;
}
static vireo_result_t inspect_client(void *ctx, vireo_connection_t const *c,
                                     vireo_connection_info_t *i) {
    fixture_t *f = ctx;
    ++f->inspect_calls;
    if (f->inspect_fail_at == f->inspect_calls)
        return VIREO_RESULT_INTERNAL;
    return vireo_connection_inspect(c, i);
}
static vireo_result_t adopt_client(void *ctx, vireo_connection_pool_t *p, vireo_connection_t **c,
                                   vireo_connection_pool_lease_t *l,
                                   vireo_connection_pool_operation_error_t *e) {
    (void)ctx;
    return vireo_connection_pool_adopt(p, c, l, e);
}
static vireo_result_t lookup_client(void *ctx, vireo_connection_pool_t const *p,
                                    vireo_connection_pool_lease_t l, vireo_connection_t **c) {
    (void)ctx;
    errno = E2BIG;
    return vireo_connection_pool_lookup(p, l, c);
}
static vireo_result_t attach_client(void *ctx, vireo_connection_t *c, vireo_event_loop_t *p,
                                    uint32_t mask, vireo_connection_callback_t cb, void *cbctx,
                                    vireo_connection_loop_error_t *e) {
    (void)ctx;
    return vireo_connection_attach(c, p, mask, cb, cbctx, e);
}
static vireo_result_t detach_client(void *ctx, vireo_connection_t *c,
                                    vireo_connection_loop_error_t *e) {
    fixture_t *f = ctx;
    if (f->detach_io) {
        *e = (vireo_connection_loop_error_t){
            .stage = VIREO_CONNECTION_LOOP_STAGE_DETACH,
            .loop_error = {.stage = VIREO_EVENT_LOOP_STAGE_DEL,
                           .epoll_error = {VIREO_EPOLL_STAGE_DEL, EINTR}}};
        return VIREO_RESULT_IO;
    }
    return vireo_connection_detach(c, e);
}
static vireo_result_t release_client(void *ctx, vireo_connection_pool_t *p,
                                     vireo_connection_pool_lease_t *l,
                                     vireo_connection_pool_operation_error_t *e) {
    fixture_t *f = ctx;
    return f->release_busy ? VIREO_RESULT_BUSY : vireo_connection_pool_release(p, l, e);
}
static vireo_result_t destroy_client(void *ctx, vireo_connection_t **c,
                                     vireo_connection_error_t *e) {
    (void)ctx;
    return vireo_connection_destroy(c, e);
}
static int close_fd(void *ctx, int fd) {
    (void)ctx;
    return close(fd);
}
static vireo_result_t receive_bytes(void *ctx, vireo_connection_t *c,
                                    vireo_connection_receive_budget_t const *b,
                                    vireo_connection_receive_info_t *i,
                                    vireo_connection_error_t *e) {
    fixture_t *f = ctx;
    ++f->receive_calls;
    vireo_connection_receive_budget_t limited = *b;
    if (f->receive_io && limited.max_bytes > 32)
        limited.max_bytes = 32;
    vireo_result_t const result = vireo_connection_receive(c, &limited, i, e);
    /* 真实前缀/实际 calls 保留，仅在 wrapper 返回边界注入 IO，不冒称 kernel EIO。 */
    if (result == VIREO_OK && f->receive_io) {
        i->stop_reason = VIREO_CONNECTION_RECEIVE_STOP_ERROR;
        *e = (vireo_connection_error_t){VIREO_CONNECTION_STAGE_RECEIVE, EIO};
        return VIREO_RESULT_IO;
    }
    return result;
}
static vireo_result_t peek_bytes(void *ctx, vireo_connection_t const *c, uint8_t const **p,
                                 size_t *n) {
    (void)ctx;
    return vireo_connection_read_peek(c, p, n);
}
static vireo_result_t consume_bytes(void *ctx, vireo_connection_t *c, size_t n) {
    (void)ctx;
    return vireo_connection_read_consume(c, n);
}
static vireo_result_t enqueue_bytes(void *ctx, vireo_connection_t *c, uint8_t const *p, size_t n,
                                    vireo_connection_error_t *e) {
    (void)ctx;
    return vireo_connection_write_enqueue(c, p, n, e);
}
static vireo_result_t send_bytes(void *ctx, vireo_connection_t *c,
                                 vireo_connection_send_budget_t const *b,
                                 vireo_connection_send_info_t *i, vireo_connection_error_t *e) {
    fixture_t *f = ctx;
    ++f->send_calls;
    vireo_connection_send_budget_t limited = *b;
    if (f->send_io && limited.max_bytes > 32)
        limited.max_bytes = 32;
    vireo_result_t const result = vireo_connection_send(c, &limited, i, e);
    /* 同上：实际发送进度先发生，IO 是返回边界注入，不虚构额外 send_calls。 */
    if (result == VIREO_OK && f->send_io) {
        i->stop_reason = VIREO_CONNECTION_SEND_STOP_ERROR;
        *e = (vireo_connection_error_t){VIREO_CONNECTION_STAGE_SEND, EINTR};
        return VIREO_RESULT_IO;
    }
    return result;
}
static vireo_result_t frame_views(void *ctx, vireo_connection_t const *c,
                                  vireo_connection_frame_options_t const *o,
                                  vireo_connection_frame_budget_t const *b,
                                  vireo_connection_frame_view_t *v, size_t n,
                                  vireo_connection_frame_info_t *i,
                                  vireo_connection_frame_error_t *e) {
    fixture_t *f = ctx;
    ++f->frame_calls;
    return vireo_connection_frames_peek(c, o, b, v, n, i, e);
}
/* 故障夹具临时违背隐藏 fd 的外部禁用规则，不能作为合法应用做法：
 * 保留同一 open-file-description，移去原 fd 使真实 MOD 得到 EBADF，
 * 立即 dup3 恢复同一 fd/key 后关闭临时副本。借用不逃逸到生产接口。
 * 不读 connection/loop 私有布局，不修改封板 seam 或生产系统状态。 */
static int fault_begin(fixture_t *f, vireo_connection_t *c, int operation) {
    ++f->policy_calls[operation - 1];
    if (f->fault_operation != operation)
        return -1;
    for (size_t k = 0; k < 2; ++k)
        if (f->objects[k] == c) {
            int const backup = fcntl(f->raw_fds[k], F_DUPFD_CLOEXEC, 0);
            REQUIRE(backup >= 0 && close(f->raw_fds[k]) == 0);
            return backup;
        }
    REQUIRE(false);
    return -1;
}
static void fault_end(fixture_t *f, vireo_connection_t *c, int backup) {
    if (backup >= 0) {
        bool found = false;
        for (size_t k = 0; k < 2; ++k)
            if (f->objects[k] == c) {
                REQUIRE(dup3(backup, f->raw_fds[k], O_CLOEXEC) == f->raw_fds[k]);
                found = true;
                break;
            }
        REQUIRE(found && close(backup) == 0);
    }
    errno = ERANGE; /* 最外层必须恢复 caller 的入口值，不能泄漏 wrapper 的 errno。 */
}
/** 只桥接公开 set_interests；不持有第二 owner、不扩展依赖策略。 */
static vireo_result_t policy_set_interests(void *ctx, vireo_connection_t *c, uint32_t interests,
                                           vireo_connection_loop_error_t *error) {
    fixture_t *f = ctx;
    int const backup = fault_begin(f, c, 1);
    vireo_result_t const result = vireo_connection_set_interests(c, interests, error);
    fault_end(f, c, backup);
    return result;
}
/** 只桥接公开 flow_configure；不持有第二 owner、不扩展依赖策略。 */
static vireo_result_t policy_flow_configure(void *ctx, vireo_connection_t *c,
                                            vireo_connection_flow_options_t const *options,
                                            vireo_connection_loop_error_t *error) {
    fixture_t *f = ctx;
    int const backup = fault_begin(f, c, 2);
    vireo_result_t const result = vireo_connection_flow_configure(c, options, error);
    fault_end(f, c, backup);
    return result;
}
/** 只桥接公开 flow_refresh；不持有第二 owner、不扩展依赖策略。 */
static vireo_result_t policy_flow_refresh(void *ctx, vireo_connection_t *c,
                                          vireo_connection_loop_error_t *error) {
    fixture_t *f = ctx;
    if (f->probe_on_sync) {
        f->probe_on_sync = false;
        probe(f, false);
    }
    int const backup = fault_begin(f, c, 3);
    vireo_result_t const result = vireo_connection_flow_refresh(c, error);
    fault_end(f, c, backup);
    return result;
}
/** 只桥接公开 flow_disable；不持有第二 owner、不扩展依赖策略。 */
static vireo_result_t policy_flow_disable(void *ctx, vireo_connection_t *c,
                                          vireo_connection_loop_error_t *error) {
    fixture_t *f = ctx;
    int const backup = fault_begin(f, c, 4);
    vireo_result_t const result = vireo_connection_flow_disable(c, error);
    fault_end(f, c, backup);
    return result;
}
/** 只桥接公开 request_close；不持有第二 owner、不扩展依赖策略。 */
static vireo_result_t policy_request_close(void *ctx, vireo_connection_t *c,
                                           vireo_connection_close_mode_t mode,
                                           vireo_connection_close_reason_t reason,
                                           vireo_connection_loop_error_t *error) {
    fixture_t *f = ctx;
    int const backup = fault_begin(f, c, 5);
    vireo_result_t const result = vireo_connection_request_close(c, mode, reason, error);
    fault_end(f, c, backup);
    return result;
}
/** 只桥接公开 close_refresh；不持有第二 owner、不扩展依赖策略。 */
static vireo_result_t policy_close_refresh(void *ctx, vireo_connection_t *c,
                                           vireo_connection_loop_error_t *error) {
    fixture_t *f = ctx;
    int const backup = fault_begin(f, c, 6);
    vireo_result_t const result = vireo_connection_close_refresh(c, error);
    fault_end(f, c, backup);
    return result;
}

static vireo_tcp_server_client_ops_t ops(fixture_t *f) {
    return (vireo_tcp_server_client_ops_t){f,
                                           accept_client,
                                           create_client,
                                           inspect_client,
                                           adopt_client,
                                           lookup_client,
                                           attach_client,
                                           detach_client,
                                           release_client,
                                           destroy_client,
                                           close_fd,
                                           receive_bytes,
                                           peek_bytes,
                                           consume_bytes,
                                           enqueue_bytes,
                                           send_bytes,
                                           frame_views,
                                           policy_set_interests,
                                           policy_flow_configure,
                                           policy_flow_refresh,
                                           policy_flow_disable,
                                           policy_request_close,
                                           policy_close_refresh};
}
static void start(fixture_t *f, int family, bool hooked, vireo_connection_options_t o,
                  size_t count) {
    static unsigned serial;
    f->family = family;
    if (hooked) {
        vireo_tcp_server_client_ops_t table = ops(f);
        REQUIRE(vireo_tcp_server_create_with_client_ops(&server_options, NULL, NULL, &table,
                                                        &f->server, NULL) == VIREO_OK);
        memset(&table, 0, sizeof(table)); /* 对象完整按值复制。 */
    } else
        REQUIRE(vireo_tcp_server_create(&server_options, &f->server, NULL) == VIREO_OK);
    int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    REQUIRE(fd >= 0);
    if (family == AF_INET) {
        struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr = {htonl(INADDR_LOOPBACK)}};
        f->length = (socklen_t)sizeof(a);
        REQUIRE(bind(fd, (struct sockaddr *)&a, f->length) == 0);
        REQUIRE(getsockname(fd, (struct sockaddr *)&f->address, &f->length) == 0);
    } else {
        struct sockaddr_un a = {.sun_family = AF_UNIX};
        int const n = snprintf(a.sun_path + 1, sizeof(a.sun_path) - 1, "vireo-byte-%ld-%u",
                               (long)getpid(), ++serial);
        REQUIRE(n > 0 && (size_t)n < sizeof(a.sun_path) - 1);
        memcpy(&f->address, &a, sizeof(a));
        f->length = (socklen_t)sizeof(a);
        REQUIRE(bind(fd, (struct sockaddr *)&f->address, f->length) == 0);
    }
    REQUIRE(listen(fd, 8) == 0);
    vireo_acceptor_options_t const aopts = {4096};
    vireo_acceptor_t *a = NULL;
    REQUIRE(vireo_acceptor_create(&aopts, &fd, &a, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_adopt_listener(f->server, &a, NULL) == VIREO_OK && a == NULL);
    for (size_t k = 0; k < count; ++k) {
        f->peers[k] = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
        REQUIRE(f->peers[k] >= 0);
        struct timeval const timeout = {2, 0};
        REQUIRE(setsockopt(f->peers[k], SOL_SOCKET, SO_RCVTIMEO, &timeout,
                           (socklen_t)sizeof(timeout)) == 0);
        REQUIRE(connect(f->peers[k], (struct sockaddr *)&f->address, f->length) == 0);
    }
    vireo_tcp_server_admit_budget_t const b = {count, count};
    vireo_tcp_server_admit_info_t i;
    REQUIRE(vireo_tcp_server_admit_batch(f->server, &o, &b, f->clients, count, &i, NULL) ==
                VIREO_OK &&
            i.admitted_count == count);
}
static void end(fixture_t *f, size_t count) {
    f->release_busy = false;
    for (size_t k = 0; k < count; ++k) {
        if (!empty(f->clients[k]))
            REQUIRE(vireo_tcp_server_release_client(f->server, &f->clients[k], NULL) == VIREO_OK);
        REQUIRE(close(f->peers[k]) == 0);
    }
    REQUIRE(vireo_tcp_server_destroy(&f->server, NULL) == VIREO_OK && f->server == NULL);
}
static vireo_tcp_server_client_info_t info(fixture_t *f, size_t n) {
    vireo_tcp_server_client_info_t i;
    REQUIRE(vireo_tcp_server_client_inspect(f->server, f->clients[n], &i) == VIREO_OK);
    return i;
}
static uint32_t const reading = VIREO_EPOLL_INTEREST_READ | VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED;
static vireo_connection_flow_options_t const flow = {96, 95, 192, 32, 96};
static void configured(fixture_t *f) {
    errno = EDOM;
    REQUIRE(vireo_tcp_server_client_flow_configure(f->server, f->clients[0], &flow, NULL) ==
            VIREO_OK);
    CHECK(errno == EDOM);
}
static void feed(fixture_t *f, size_t k, uint8_t const *bytes, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        ssize_t const n = send(f->peers[k], bytes + offset, size - offset, MSG_NOSIGNAL);
        REQUIRE(n > 0);
        offset += (size_t)n;
    }
    vireo_connection_receive_info_t i;
    REQUIRE(vireo_tcp_server_client_receive(f->server, f->clients[k], &read_budget, &i, NULL) ==
            VIREO_OK);
    REQUIRE(i.received_bytes == size);
}
static void queue(fixture_t *f, size_t size) {
    uint8_t bytes[128];
    memset(bytes, 91, sizeof(bytes));
    REQUIRE(size <= sizeof(bytes));
    REQUIRE(vireo_tcp_server_client_write_enqueue(f->server, f->clients[0], bytes, size, NULL) ==
            VIREO_OK);
}

static vireo_tcp_server_process_options_t const limits = {96, 96};
static vireo_tcp_server_drive_budget_t const allowance = {
    {SIZE_MAX, 8}, {2, 192, 192}, {SIZE_MAX, 8}};
static void request_bytes(uint8_t wire[32], uint32_t sequence) {
    vireo_protocol_header_t h = {.command = VIREO_COMMAND_PING, .sequence = sequence};
    REQUIRE(vireo_protocol_header_encode(&h, wire, 32) == VIREO_OK);
    REQUIRE(vireo_protocol_frame_crc32c_calculate(wire, 32, NULL, 0, &h.crc32c) == VIREO_OK);
    REQUIRE(vireo_protocol_header_encode(&h, wire, 32) == VIREO_OK);
}
static void requests(fixture_t *f, unsigned count) {
    uint8_t bytes[256];
    REQUIRE(count <= 8);
    for (unsigned k = 0; k < count; ++k)
        request_bytes(bytes + k * 32, k + 1);
    feed(f, 0, bytes, (size_t)count * 32);
}
typedef struct handler_data {
    fixture_t *fixture, *nested;
    unsigned calls, fail_at;
    bool probe;
} handler_data_t;
static vireo_result_t reply(vireo_connection_frame_view_t const *request, uint8_t *body,
                            size_t capacity, vireo_tcp_server_reply_t *description, void *context);
static vireo_result_t drive(fixture_t *f, size_t client, vireo_tcp_server_drive_budget_t b,
                            handler_data_t *h, vireo_tcp_server_drive_info_t *i,
                            vireo_tcp_server_drive_error_t *e) {
    uint8_t workspace[96];
    errno = EDOM;
    vireo_result_t const result = vireo_tcp_server_client_drive(
        f->server, f->clients[client], &limits, &b, workspace, sizeof(workspace), reply, h, i, e);
    CHECK(errno == EDOM);
    return result;
}
static vireo_result_t reply(vireo_connection_frame_view_t const *request, uint8_t *body,
                            size_t capacity, vireo_tcp_server_reply_t *description, void *context) {
    (void)body;
    (void)capacity;
    handler_data_t *h = context;
    ++h->calls;
    CHECK(request->wire_size == 32 && request->header.command == VIREO_COMMAND_PING);
    description->body_size = 0;
    if (h->probe)
        probe(h->fixture, true);
    if (h->nested != NULL) {
        handler_data_t inner = {0};
        vireo_tcp_server_drive_info_t i;
        CHECK(drive(h->nested, 0, allowance, &inner, &i, NULL) == VIREO_OK);
        CHECK(inner.calls == 1 && i.process.consumed_requests == 1);
        h->nested = NULL;
    }
    errno = ERANGE;
    return h->fail_at == h->calls ? VIREO_RESULT_IO : VIREO_OK;
}
static void read_responses(fixture_t *f, size_t client, unsigned count, uint32_t first_sequence) {
    for (unsigned k = 0; k < count; ++k) {
        uint8_t wire[32];
        size_t offset = 0;
        while (offset < sizeof(wire)) {
            ssize_t const n = recv(f->peers[client], wire + offset, sizeof(wire) - offset, 0);
            REQUIRE(n > 0);
            offset += (size_t)n;
        }
        vireo_protocol_header_t h;
        vireo_protocol_codec_issue_t issue;
        CHECK(vireo_protocol_header_decode(wire, sizeof(wire), &h, &issue) == VIREO_OK);
        CHECK(vireo_protocol_response_header_validate(&h, &issue) == VIREO_OK);
        uint32_t crc = 0;
        REQUIRE(vireo_protocol_frame_crc32c_calculate(wire, sizeof(wire), NULL, 0, &crc) ==
                VIREO_OK);
        CHECK(h.crc32c == crc && h.body_len == 0 && h.command == VIREO_COMMAND_PING);
        CHECK(h.sequence == first_sequence + (uint32_t)k &&
              h.flags == VIREO_PROTOCOL_FLAG_RESPONSE && h.status == VIREO_STATUS_OK);
    }
}
static void idle(fixture_t *f) {
    vireo_tcp_server_info_t s;
    REQUIRE(vireo_tcp_server_inspect(f->server, &s) == VIREO_OK);
    CHECK(!s.driving_active && !s.processing_active);
}
static void parameters(void) {
    ++groups;
    fixture_t f = {0};
    start(&f, AF_INET, true, connection_options, 1);
    uint8_t work[160], original[160];
    memset(work, 0xA5, sizeof(work));
    memcpy(original, work, sizeof(work));
    handler_data_t h = {0};
    vireo_tcp_server_drive_info_t i, saved;
    memset(&saved, 0x5A, sizeof(saved));
    for (unsigned k = 0; k < 20; ++k) {
        vireo_tcp_server_drive_budget_t b = allowance;
        vireo_tcp_server_process_options_t o = limits;
        vireo_connection_pool_lease_t l = f.clients[0];
        size_t cap = 96;
        vireo_result_t expected = VIREO_RESULT_RANGE;
        if (k == 0)
            b.receive.max_bytes = 0;
        if (k == 1)
            b.receive.max_syscalls = 0;
        if (k == 2)
            b.send.max_bytes = 0;
        if (k == 3)
            b.send.max_syscalls = 0;
        if (k == 4)
            b.process.max_messages = 0;
        if (k == 5)
            b.process.max_request_bytes = 95;
        if (k == 6)
            b.process.max_response_bytes = 95;
        if (k == 7)
            o.max_request_frame_bytes = 31;
        if (k == 8)
            o.max_response_frame_bytes = SIZE_MAX;
        if (k == 9)
            cap = 95;
        if (k == 10) {
            o.max_request_frame_bytes = 257;
            b.process.max_request_bytes = 257;
        }
        if (k == 11) {
            o.max_response_frame_bytes = 129;
            b.process.max_response_bytes = 129;
            cap = 129;
        }
        if (k == 12) {
            l = (vireo_connection_pool_lease_t){0};
            expected = VIREO_RESULT_NOT_FOUND;
        }
        if (k == 13) {
            ++l.pool_id;
            expected = VIREO_RESULT_INVALID_ARGUMENT;
        }
        if (k == 14)
            l.slot_index = 2;
        if (k == 15) {
            ++l.generation;
            expected = VIREO_RESULT_NOT_FOUND;
        }
        if (k >= 16)
            expected = VIREO_RESULT_INVALID_ARGUMENT;
        memcpy(&i, &saved, sizeof(i));
        errno = EDOM;
        CHECK(vireo_tcp_server_client_drive(f.server, l, k == 16 ? NULL : &o, k == 17 ? NULL : &b,
                                            k == 18 ? NULL : work, cap, k == 19 ? NULL : reply, &h,
                                            &i, NULL) == expected &&
              errno == EDOM);
        CHECK(memcmp(&i, &saved, sizeof(i)) == 0 && memcmp(work, original, sizeof(work)) == 0);
    }
    memcpy(&i, &saved, sizeof(i));
    CHECK(drive(&f, 0, allowance, &h, &i, NULL) == VIREO_RESULT_NOT_FOUND);
    CHECK(memcmp(&i, &saved, sizeof(i)) == 0 && h.calls == 0 && f.receive_calls == 0 &&
          f.send_calls == 0);
    configured(&f);
    vireo_tcp_server_process_options_t o = {97, 96};
    CHECK(vireo_tcp_server_client_drive(f.server, f.clients[0], &o, &allowance, work, sizeof(work),
                                        reply, &h, &i, NULL) == VIREO_RESULT_RANGE);
    CHECK(memcmp(&i, &saved, sizeof(i)) == 0);
    CHECK(vireo_tcp_server_client_drive(NULL, f.clients[0], &limits, &allowance, work, sizeof(work),
                                        reply, &h, &i, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_tcp_server_client_drive(f.server, f.clients[0], &limits, &allowance, work,
                                        sizeof(work), reply, &h, NULL,
                                        NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    idle(&f);
    end(&f, 1);
}
static void cached_rounds(void) {
    ++groups;
    fixture_t f = {0};
    start(&f, AF_INET, true, connection_options, 2);
    requests(&f, 7);
    configured(&f);
    CHECK(info(&f, 0).connection_info.read_pressure &&
          info(&f, 0).connection_info.loop_interests == 0);
    REQUIRE(vireo_tcp_server_client_flow_configure(f.server, f.clients[1], &flow, NULL) ==
            VIREO_OK);
    uint8_t wire[32];
    request_bytes(wire, 99);
    feed(&f, 1, wire, sizeof(wire));
    handler_data_t h = {0}, other = {0};
    vireo_tcp_server_drive_info_t i;
    size_t const remain[] = {160, 96, 32, 0};
    for (unsigned k = 0; k < 4; ++k) {
        CHECK(drive(&f, 0, allowance, &h, &i, NULL) == VIREO_OK);
        CHECK(i.process.consumed_requests == (k == 3 ? 1U : 2U));
        CHECK(i.needs_processing == (k != 3));
        CHECK(info(&f, 0).connection_info.read_buffer.readable_size == remain[k]);
        if (k < 3)
            CHECK(!i.receive_called); /* 即使没有 READ，新轮仍处理用户缓存。 */
        if (k == 0) {
            CHECK(drive(&f, 1, allowance, &other, &i, NULL) == VIREO_OK);
            CHECK(other.calls == 1);
        }
    }
    CHECK(h.calls == 7);
    read_responses(&f, 0, 7, 1);
    read_responses(&f, 1, 1, 99);
    idle(&f);
    end(&f, 2);
}
static void half_and_budget(void) {
    ++groups;
    for (unsigned mode = 0; mode < 4; ++mode) {
        fixture_t f = {0};
        start(&f, AF_INET, true, connection_options, 1);
        configured(&f);
        uint8_t wire[64];
        request_bytes(wire, 1);
        request_bytes(wire + 32, 2);
        if (mode > 0)
            wire[63] ^= 1;
        feed(&f, 0, wire, mode == 0 ? 48 : 64);
        vireo_tcp_server_drive_budget_t b = allowance;
        if (mode <= 1)
            b.process.max_messages = 1;
        if (mode == 2)
            b.process.max_request_bytes = 96;
        if (mode == 3)
            b.process.max_response_bytes = 96;
        handler_data_t h = {0};
        vireo_tcp_server_drive_info_t i;
        unsigned const peeks = f.frame_calls;
        CHECK(drive(&f, 0, b, &h, &i, NULL) == VIREO_OK && i.needs_processing);
        CHECK(i.process.consumed_requests == 1 && f.frame_calls == peeks + 1);
        CHECK(drive(&f, 0, allowance, &h, &i, NULL) ==
              (mode == 0 ? VIREO_OK : VIREO_RESULT_PROTOCOL));
        CHECK(!i.needs_processing && h.calls == 1);
        if (mode == 0)
            CHECK(i.process.stop_reason == VIREO_TCP_SERVER_PROCESS_NEED_MORE);
        read_responses(&f, 0, 1, 1);
        end(&f, 1);
    }
}
static void eof(void) {
    ++groups;
    for (unsigned mode = 0; mode < 2; ++mode) {
        fixture_t f = {0};
        start(&f, AF_INET, true, connection_options, 1);
        configured(&f);
        uint8_t wire[39];
        request_bytes(wire, 1);
        memset(wire + 32, 0, 7);
        feed(&f, 0, wire, mode == 0 ? 32 : 39);
        REQUIRE(shutdown(f.peers[0], SHUT_WR) == 0);
        handler_data_t h = {0};
        vireo_tcp_server_drive_info_t i;
        vireo_tcp_server_drive_error_t e;
        CHECK(drive(&f, 0, allowance, &h, &i, &e) ==
              (mode == 0 ? VIREO_OK : VIREO_RESULT_PROTOCOL));
        CHECK(info(&f, 0).connection_info.read_eof &&
              info(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
        CHECK(h.calls == 1 && i.process.consumed_requests == 1 && !i.needs_processing);
        if (mode == 0) {
            CHECK(i.send_called && i.process.stop_reason == VIREO_TCP_SERVER_PROCESS_EOF);
            read_responses(&f, 0, 1, 1);
        } else {
            CHECK(!i.send_called && e.primary_stage == VIREO_TCP_SERVER_DRIVE_PROCESS &&
                  e.primary_error.primary.frame_error.issue ==
                      VIREO_CONNECTION_FRAME_ISSUE_TRUNCATED);
        }
        end(&f, 1);
    }
}
static void pre_sync_failure(void) {
    ++groups;
    fixture_t f = {0};
    start(&f, AF_INET, true, connection_options, 1);
    configured(&f);
    queue(&f, 100);
    unsigned const sync = f.policy_calls[2];
    f.fault_operation = 3;
    handler_data_t h = {0};
    vireo_tcp_server_drive_info_t i;
    vireo_tcp_server_drive_error_t e;
    CHECK(drive(&f, 0, allowance, &h, &i, &e) == VIREO_RESULT_IO);
    CHECK(e.primary_stage == VIREO_TCP_SERVER_DRIVE_PRE_SYNC &&
          e.primary_error.primary.loop_error.loop_error.epoll_error.system_errno == EBADF);
    CHECK(e.sync_result == VIREO_OK && !i.receive_called && !i.process_called && !i.send_called);
    CHECK(f.policy_calls[2] == sync + 1 && h.calls == 0 &&
          info(&f, 0).connection_info.loop_interests == reading);
    f.fault_operation = 0;
    idle(&f);
    end(&f, 1);
}
static void partial_receive(void) {
    ++groups;
    fixture_t f = {0};
    start(&f, AF_INET, true, connection_options, 1);
    configured(&f);
    uint8_t wire[64];
    request_bytes(wire, 1);
    request_bytes(wire + 32, 2);
    REQUIRE(send(f.peers[0], wire, sizeof(wire), MSG_NOSIGNAL) == 64);
    f.receive_io = true;
    handler_data_t h = {0};
    vireo_tcp_server_drive_info_t i;
    vireo_tcp_server_drive_error_t e;
    CHECK(drive(&f, 0, allowance, &h, &i, &e) == VIREO_RESULT_IO);
    CHECK(i.receive_called && i.receive.received_bytes == 32 && !i.process_called &&
          !i.send_called && h.calls == 0);
    CHECK(e.primary_stage == VIREO_TCP_SERVER_DRIVE_RECEIVE &&
          e.primary_error.primary.connection_error.system_errno == EIO &&
          e.sync_result == VIREO_OK);
    CHECK(info(&f, 0).connection_info.read_buffer.readable_size == 32 && !i.needs_processing);
    f.receive_io = false;
    CHECK(drive(&f, 0, allowance, &h, &i, NULL) == VIREO_OK && h.calls == 2);
    read_responses(&f, 0, 2, 1);
    idle(&f);
    end(&f, 1);
}
static void process_and_sync_failure(void) {
    ++groups;
    fixture_t f = {0};
    start(&f, AF_INET, true, connection_options, 1);
    configured(&f);
    requests(&f, 2);
    f.fault_operation = 3;
    unsigned const sync = f.policy_calls[2];
    handler_data_t h = {.fail_at = 2};
    vireo_tcp_server_drive_info_t i;
    vireo_tcp_server_drive_error_t e;
    CHECK(drive(&f, 0, allowance, &h, &i, &e) == VIREO_RESULT_IO);
    CHECK(i.process.handler_calls == 2 && i.process.enqueued_responses == 1 &&
          i.process.consumed_requests == 1 && !i.send_called);
    CHECK(e.primary_stage == VIREO_TCP_SERVER_DRIVE_PROCESS &&
          e.primary_error.primary.stage == VIREO_TCP_SERVER_CLIENT_HANDLER &&
          e.primary_error.primary.handler_result == VIREO_RESULT_IO);
    CHECK(e.sync_result == VIREO_RESULT_IO &&
          e.sync_error.primary.stage == VIREO_TCP_SERVER_CLIENT_FLOW_REFRESH &&
          e.sync_error.primary.loop_error.loop_error.epoll_error.system_errno == EBADF);
    CHECK(f.policy_calls[2] == sync + 2 &&
          info(&f, 0).connection_info.write_buffer.readable_size == 32 && !i.needs_processing);
    f.fault_operation = 0;
    idle(&f);
    end(&f, 1);
}
static void send_and_sync_failure(void) {
    ++groups;
    fixture_t f = {0};
    start(&f, AF_INET, true, connection_options, 1);
    configured(&f);
    requests(&f, 2);
    f.send_io = true;
    f.fault_operation = 3;
    handler_data_t h = {0};
    vireo_tcp_server_drive_info_t i;
    vireo_tcp_server_drive_error_t e;
    CHECK(drive(&f, 0, allowance, &h, &i, &e) == VIREO_RESULT_IO);
    CHECK(i.send_called && i.send.sent_bytes == 32 && i.process.consumed_requests == 2);
    CHECK(e.primary_stage == VIREO_TCP_SERVER_DRIVE_SEND &&
          e.primary_error.primary.connection_error.system_errno == EINTR &&
          e.sync_result == VIREO_RESULT_IO);
    CHECK(info(&f, 0).connection_info.write_buffer.readable_size == 32 && !i.ready_to_release);
    f.send_io = false;
    f.fault_operation = 0;
    CHECK(drive(&f, 0, allowance, &h, &i, NULL) == VIREO_OK && h.calls == 2 &&
          i.send.sent_bytes == 32);
    read_responses(&f, 0, 2, 1);
    end(&f, 1);
}
static void final_sync_only(void) {
    ++groups;
    fixture_t f = {0};
    start(&f, AF_INET, true, connection_options, 1);
    configured(&f);
    requests(&f, 2);
    f.fault_operation = 3;
    vireo_tcp_server_drive_budget_t b = allowance;
    b.send.max_bytes = 32;
    handler_data_t h = {0};
    vireo_tcp_server_drive_info_t i;
    vireo_tcp_server_drive_error_t e;
    CHECK(drive(&f, 0, b, &h, &i, &e) == VIREO_RESULT_IO);
    CHECK(e.primary_stage == VIREO_TCP_SERVER_DRIVE_FINAL_SYNC && e.sync_result == VIREO_OK);
    CHECK(i.process.consumed_requests == 2 && i.send.sent_bytes == 32 && !i.needs_processing);
    f.fault_operation = 0;
    CHECK(drive(&f, 0, allowance, &h, &i, NULL) == VIREO_OK && h.calls == 2);
    read_responses(&f, 0, 2, 1);
    end(&f, 1);
}
static void inspect_failures(void) {
    ++groups;
    for (unsigned k = 1; k <= 4; ++k) {
        fixture_t f = {0};
        start(&f, AF_INET, true, connection_options, 1);
        configured(&f);
        f.inspect_fail_at = f.inspect_calls + k;
        handler_data_t h = {0};
        vireo_tcp_server_drive_info_t i, saved;
        memset(&saved, 0x5A, sizeof(saved));
        memcpy(&i, &saved, sizeof(i));
        vireo_tcp_server_drive_error_t e;
        unsigned const sync = f.policy_calls[2];
        CHECK(drive(&f, 0, allowance, &h, &i, &e) == VIREO_RESULT_INTERNAL &&
              e.primary_stage ==
                  (k == 3 ? VIREO_TCP_SERVER_DRIVE_PROCESS : VIREO_TCP_SERVER_DRIVE_INSPECT));
        if (k == 1)
            CHECK(memcmp(&i, &saved, sizeof(i)) == 0);
        if (k == 2)
            CHECK(!i.receive_called && f.policy_calls[2] == sync + 1);
        if (k >= 3)
            CHECK(!i.needs_processing && f.policy_calls[2] == sync + 2);
        f.inspect_fail_at = 0;
        idle(&f);
        end(&f, 1);
    }
}
static void drain_and_ready(void) {
    ++groups;
    fixture_t f = {0};
    start(&f, AF_INET, true, connection_options, 1);
    queue(&f, 100);
    REQUIRE(vireo_tcp_server_client_request_close(
                f.server, f.clients[0], VIREO_CONNECTION_CLOSE_MODE_DRAIN,
                VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    vireo_tcp_server_drive_budget_t b = allowance;
    b.send.max_bytes = 40;
    handler_data_t h = {0};
    vireo_tcp_server_drive_info_t i;
    CHECK(drive(&f, 0, b, &h, &i, NULL) == VIREO_OK && i.send.sent_bytes == 40 &&
          !i.ready_to_release);
    CHECK(!i.receive_called && !i.process_called && h.calls == 0);
    CHECK(drive(&f, 0, allowance, &h, &i, NULL) == VIREO_OK && i.send.sent_bytes == 60 &&
          i.ready_to_release);
    CHECK(drive(&f, 0, allowance, &h, &i, NULL) == VIREO_OK && i.ready_to_release &&
          !i.send_called);
    vireo_tcp_server_info_t s;
    REQUIRE(vireo_tcp_server_inspect(f.server, &s) == VIREO_OK);
    CHECK(s.connection_count == 1 && s.buffer_capacity_bytes == 384 &&
          s.registered_connections == 1);
    uint8_t bytes[100];
    size_t offset = 0;
    while (offset < sizeof(bytes)) {
        ssize_t n = recv(f.peers[0], bytes + offset, sizeof(bytes) - offset, 0);
        REQUIRE(n > 0);
        offset += (size_t)n;
    }
    for (size_t k = 0; k < sizeof(bytes); ++k)
        CHECK(bytes[k] == 91);
    CHECK(vireo_tcp_server_destroy(&f.server, NULL) == VIREO_RESULT_BUSY);
    end(&f, 1);
}
static void ready_repairs(void) {
    ++groups;
    fixture_t f = {0};
    start(&f, AF_INET, true, connection_options, 1);
    configured(&f);
    uint8_t wire[16] = {0};
    feed(&f, 0, wire, sizeof(wire));
    uint8_t const *borrow = NULL;
    size_t size = 0;
    REQUIRE(vireo_tcp_server_client_read_peek(f.server, f.clients[0], &borrow, &size, NULL) ==
            VIREO_OK);
    f.fault_operation = 5;
    CHECK(vireo_tcp_server_client_request_close(
              f.server, f.clients[0], VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
              VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_RESULT_IO);
    CHECK(info(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_READY &&
          info(&f, 0).connection_info.loop_interests == reading);
    f.fault_operation = 6;
    handler_data_t h = {0};
    vireo_tcp_server_drive_info_t i;
    vireo_tcp_server_drive_error_t e;
    CHECK(drive(&f, 0, allowance, &h, &i, &e) == VIREO_RESULT_IO &&
          e.primary_stage == VIREO_TCP_SERVER_DRIVE_FINAL_SYNC && !i.ready_to_release);
    f.fault_operation = 0;
    CHECK(drive(&f, 0, allowance, &h, &i, NULL) == VIREO_OK && i.ready_to_release);
    CHECK(!i.receive_called && !i.process_called && !i.send_called &&
          memcmp(borrow, wire, size) == 0 && size == 16);
    CHECK(info(&f, 0).connection_info.loop_interests == 0);
    end(&f, 1);
}
static void stalled_write(void) {
    ++groups;
    fixture_t f = {0};
    start(&f, AF_UNIX, true, connection_options, 1);
    int const small = 4096;
    REQUIRE(setsockopt(f.raw_fds[0], SOL_SOCKET, SO_SNDBUF, &small, (socklen_t)sizeof(small)) == 0);
    bool blocked = false;
    for (unsigned round = 0; round < 4096; ++round) {
        vireo_tcp_server_client_info_t ci = info(&f, 0);
        if (ci.connection_info.write_buffer.readable_size == 0)
            queue(&f, 128);
        vireo_connection_send_info_t si;
        REQUIRE(vireo_tcp_server_client_send(f.server, f.clients[0], &write_budget, &si, NULL) ==
                VIREO_OK);
        if (si.stop_reason == VIREO_CONNECTION_SEND_STOP_WOULD_BLOCK) {
            blocked = true;
            break;
        }
    }
    REQUIRE(blocked);
    requests(&f, 1);
    configured(&f);
    handler_data_t h = {0};
    vireo_tcp_server_drive_info_t i;
    CHECK(drive(&f, 0, allowance, &h, &i, NULL) == VIREO_OK &&
          i.process.stop_reason == VIREO_TCP_SERVER_PROCESS_WRITE_FULL &&
          i.send.stop_reason == VIREO_CONNECTION_SEND_STOP_WOULD_BLOCK);
    CHECK(!i.needs_processing && h.calls == 0 && !i.receive_called &&
          info(&f, 0).connection_info.loop_interests == VIREO_EPOLL_INTEREST_WRITE);
    uint8_t bytes[4096];
    for (;;) {
        ssize_t n = recv(f.peers[0], bytes, sizeof(bytes), MSG_DONTWAIT);
        if (n < 0) {
            REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);
            break;
        }
        REQUIRE(n > 0);
    }
    CHECK(drive(&f, 0, allowance, &h, &i, NULL) == VIREO_OK && i.needs_processing && h.calls == 0);
    CHECK(drive(&f, 0, allowance, &h, &i, NULL) == VIREO_OK && h.calls == 1 && !i.needs_processing);
    end(&f, 1);
}
static void probe(fixture_t *f, bool processing) {
    vireo_tcp_server_info_t s;
    REQUIRE(vireo_tcp_server_inspect(f->server, &s) == VIREO_OK);
    CHECK(s.driving_active && s.processing_active == processing);
    uint8_t work[96];
    vireo_tcp_server_drive_info_t di;
    vireo_tcp_server_process_info_t pi;
    handler_data_t h = {0};
    CHECK(vireo_tcp_server_client_drive(f->server, f->clients[0], &limits, &allowance, work,
                                        sizeof(work), reply, &h, &di, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_client_process(f->server, f->clients[0], &limits, &allowance.process,
                                          work, sizeof(work), reply, &h, &pi,
                                          NULL) == VIREO_RESULT_BUSY);
    for (size_t k = 0; k < 2; ++k) {
        vireo_connection_receive_info_t ri;
        vireo_connection_send_info_t si;
        CHECK(vireo_tcp_server_client_receive(f->server, f->clients[k], &read_budget, &ri, NULL) ==
              VIREO_RESULT_BUSY);
        CHECK(vireo_tcp_server_client_send(f->server, f->clients[k], &write_budget, &si, NULL) ==
              VIREO_RESULT_BUSY);
        CHECK(vireo_tcp_server_client_read_consume(f->server, f->clients[k], 0, NULL) ==
              VIREO_RESULT_BUSY);
        CHECK(vireo_tcp_server_client_write_enqueue(f->server, f->clients[k], NULL, 0, NULL) ==
              VIREO_RESULT_BUSY);
        vireo_connection_pool_lease_t l = f->clients[k];
        CHECK(vireo_tcp_server_release_client(f->server, &l, NULL) == VIREO_RESULT_BUSY &&
              same(l, f->clients[k]));
        CHECK(vireo_tcp_server_client_set_interests(f->server, l, reading, NULL) ==
              VIREO_RESULT_BUSY);
        CHECK(vireo_tcp_server_client_flow_configure(f->server, l, &flow, NULL) ==
              VIREO_RESULT_BUSY);
        CHECK(vireo_tcp_server_client_flow_refresh(f->server, l, NULL) == VIREO_RESULT_BUSY);
        CHECK(vireo_tcp_server_client_flow_disable(f->server, l, NULL) == VIREO_RESULT_BUSY);
        CHECK(vireo_tcp_server_client_request_close(f->server, l, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
                                                    VIREO_CONNECTION_CLOSE_REASON_APPLICATION,
                                                    NULL) == VIREO_RESULT_BUSY);
        CHECK(vireo_tcp_server_client_close_refresh(f->server, l, NULL) == VIREO_RESULT_BUSY);
        vireo_tcp_server_client_info_t ci;
        CHECK(vireo_tcp_server_client_inspect(f->server, l, &ci) == VIREO_OK);
        uint8_t const *p = NULL;
        size_t n = 0;
        CHECK(vireo_tcp_server_client_read_peek(f->server, l, &p, &n, NULL) == VIREO_OK);
        vireo_connection_frame_options_t fo = {VIREO_CONNECTION_FRAME_REQUEST, 96};
        vireo_connection_frame_budget_t fb = {1, 96};
        vireo_connection_frame_view_t v;
        vireo_connection_frame_info_t fi;
        CHECK(vireo_tcp_server_client_frames_peek(f->server, l, &fo, &fb, &v, 1, &fi, NULL) ==
              VIREO_OK);
    }
    vireo_acceptor_t *spare = f->spare;
    CHECK(vireo_tcp_server_adopt_listener(f->server, &spare, NULL) == VIREO_RESULT_BUSY &&
          spare == f->spare);
    CHECK(vireo_tcp_server_bind_listener(f->server, true, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_set_listener_read_enabled(f->server, false, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_unbind_listener(f->server, NULL) == VIREO_RESULT_BUSY);
    vireo_tcp_server_admit_budget_t ab = {1, 1};
    vireo_tcp_server_admit_info_t ai;
    vireo_connection_pool_lease_t out = {0};
    CHECK(vireo_tcp_server_admit_batch(f->server, &connection_options, &ab, &out, 1, &ai, NULL) ==
          VIREO_RESULT_BUSY);
    vireo_tcp_server_t *owner = f->server;
    CHECK(vireo_tcp_server_destroy(&owner, NULL) == VIREO_RESULT_BUSY && owner == f->server);
}
static void reentry(void) {
    ++groups;
    fixture_t f = {0}, g = {0};
    start(&f, AF_INET, true, connection_options, 2);
    start(&g, AF_INET, true, connection_options, 1);
    configured(&f);
    configured(&g);
    requests(&f, 1);
    requests(&g, 1);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    REQUIRE(fd >= 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr = {htonl(INADDR_LOOPBACK)}};
    REQUIRE(bind(fd, (struct sockaddr *)&addr, (socklen_t)sizeof(addr)) == 0 && listen(fd, 1) == 0);
    vireo_acceptor_options_t ao = {4096};
    REQUIRE(vireo_acceptor_create(&ao, &fd, &f.spare, NULL) == VIREO_OK);
    f.probe_on_sync = true;
    handler_data_t h = {.fixture = &f, .nested = &g, .probe = true};
    vireo_tcp_server_drive_info_t i;
    CHECK(drive(&f, 0, allowance, &h, &i, NULL) == VIREO_OK && h.calls == 1 && h.nested == NULL);
    idle(&f);
    idle(&g);
    read_responses(&f, 0, 1, 1);
    read_responses(&g, 0, 1, 1);
    REQUIRE(vireo_acceptor_destroy(&f.spare, NULL) == VIREO_OK);
    end(&f, 2);
    end(&g, 1);
}
static void reuse_and_unbound(void) {
    ++groups;
    fixture_t f = {0};
    start(&f, AF_INET, true, connection_options, 1);
    vireo_connection_pool_lease_t old = f.clients[0];
    REQUIRE(vireo_tcp_server_release_client(f.server, &f.clients[0], NULL) == VIREO_OK);
    REQUIRE(close(f.peers[0]) == 0);
    f.peers[0] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(f.peers[0] >= 0);
    REQUIRE(connect(f.peers[0], (struct sockaddr *)&f.address, f.length) == 0);
    vireo_tcp_server_admit_budget_t ab = {1, 2};
    vireo_tcp_server_admit_info_t ai;
    REQUIRE(vireo_tcp_server_admit_batch(f.server, &connection_options, &ab, f.clients, 1, &ai,
                                         NULL) == VIREO_OK &&
            ai.admitted_count == 1);
    CHECK(old.slot_index == f.clients[0].slot_index && old.generation != f.clients[0].generation);
    configured(&f);
    uint8_t work[96];
    handler_data_t h = {0};
    vireo_tcp_server_drive_info_t i;
    CHECK(vireo_tcp_server_client_drive(f.server, old, &limits, &allowance, work, sizeof(work),
                                        reply, &h, &i, NULL) == VIREO_RESULT_NOT_FOUND);
    f.release_busy = true;
    CHECK(vireo_tcp_server_release_client(f.server, &f.clients[0], NULL) == VIREO_RESULT_BUSY);
    CHECK(!info(&f, 0).connection_info.loop_attached);
    CHECK(drive(&f, 0, allowance, &h, &i, NULL) == VIREO_RESULT_NOT_FOUND);
    queue(&f, 100); /* 解绑后的 DRAINING 仍可有界发送，不要求 flow。 */
    REQUIRE(vireo_tcp_server_client_request_close(
                f.server, f.clients[0], VIREO_CONNECTION_CLOSE_MODE_DRAIN,
                VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    CHECK(drive(&f, 0, allowance, &h, &i, NULL) == VIREO_OK && i.ready_to_release &&
          i.send_called && i.send.sent_bytes == 100);
    end(&f, 1);
}
static void exact_budget(void) {
    ++groups;
    vireo_tcp_server_t *owner = NULL;
    vireo_tcp_server_info_t i;
    REQUIRE(vireo_tcp_server_create(&server_options, &owner, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_inspect(owner, &i) == VIREO_OK);
    REQUIRE(vireo_tcp_server_destroy(&owner, NULL) == VIREO_OK);
    vireo_tcp_server_options_t o = server_options;
    o.max_memory_bytes = i.allocation_bytes;
    CHECK(vireo_tcp_server_create(&o, &owner, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_destroy(&owner, NULL) == VIREO_OK);
    --o.max_memory_bytes;
    CHECK(vireo_tcp_server_create(&o, &owner, NULL) == VIREO_RESULT_RANGE && owner == NULL);
}
int main(void) {
    unsigned const before = fd_count();
    parameters();
    cached_rounds();
    half_and_budget();
    eof();
    pre_sync_failure();
    partial_receive();
    process_and_sync_failure();
    send_and_sync_failure();
    final_sync_only();
    inspect_failures();
    drain_and_ready();
    ready_repairs();
    stalled_write();
    reentry();
    reuse_and_unbound();
    exact_budget();
    unsigned const after = fd_count();
    CHECK(after == before);
    printf("tcp_server client drive: %u groups, %u failures, fd %u->%u\n", groups, failures, before,
           after);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
