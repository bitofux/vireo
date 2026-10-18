/*
- PROJECT : VIREO
- FILE    : test_tls_connection.c
- AUTHOR  : bitofux
- DATE    : 2026-10-17
- BRIEF   : 此模块负责：
- -- 用真实OpenSSL/socket验证资源寿命，以own缝分列确定性失败
 */
#define _GNU_SOURCE
#include "tls_connection_internal.h"
#include "tls_context_internal.h"
#include "tls_context_fixtures.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <openssl/err.h>

#define CHECK(condition) do { if (!(condition)) { \
    (void)fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); abort(); \
} } while (0)
#define EXPECT(expression, expected) do { errno = ECHILD; \
    vireo_result_t actual_result = (expression); \
    CHECK(actual_result == (expected)); CHECK(errno == ECHILD); \
} while (0)

/** 公共非秘密测试材料，不使用部署凭据；不执行网络证书验证。 */
static vireo_tls_context_t *make_context(void)
{
    vireo_tls_context_options_t options = {fixture_leaf, sizeof(fixture_leaf) - 1,
        fixture_key, sizeof(fixture_key) - 1, 4096};
    vireo_tls_context_t *context = NULL;
    EXPECT(vireo_tls_context_create_server(&options, &context, NULL), VIREO_OK);
    return context;
}

/** 每次创建真实独立socket，资格flags由测试自己设置而非被测对象补设。 */
static void make_pair(int pair[2])
{
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
}

/** 所有者只在TLS借用结束后关闭，真实EBADF或重复close均使测试失败。 */
static void close_pair(int const pair[2])
{
    CHECK(close(pair[0]) == 0);
    CHECK(close(pair[1]) == 0);
}

/** 同一/proc目录枚举开销在前后相同；仅为有限fd泄漏证据。 */
static size_t fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    CHECK(directory != NULL);
    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            ++count;
        }
    }
    CHECK(closedir(directory) == 0);
    return count;
}

/** 无握手/close_notify字节，也不能偷偷关闭借用socket使peer看到EOF。 */
static void peer_has_no_bytes(int peer_fd)
{
    unsigned char byte;
    CHECK(recv(peer_fd, &byte, 1, MSG_DONTWAIT) == -1);
    CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
}

/** 三个公共入口真实协作；fd flags/数目和空peer贯穿构造/观察/销毁。 */
static void lifecycle_and_no_network(void)
{
    vireo_tls_context_t *context = make_context();
    int pair[2]; make_pair(pair);
    int flags = fcntl(pair[0], F_GETFL);
    int descriptor_flags = fcntl(pair[0], F_GETFD);
    size_t before = fd_count();
    vireo_tls_connection_options_t options = {4096};
    vireo_tls_connection_t *owner = NULL;
    vireo_tls_connection_error_t error;
    EXPECT(vireo_tls_connection_create_server(context, &options, pair[0], &owner, &error), VIREO_OK);
    CHECK(owner != NULL && error.stage == VIREO_TLS_CONNECTION_STAGE_NONE);
    CHECK(error.system_errno == 0 && error.openssl_error_code == 0 && !error.has_more_errors);
    CHECK(SSL_get_rbio(owner->native) == SSL_get_wbio(owner->native));
    CHECK(BIO_get_close(SSL_get_rbio(owner->native)) == BIO_NOCLOSE);
    CHECK(SSL_get_rfd(owner->native) == pair[0] && SSL_get_wfd(owner->native) == pair[0]);
    vireo_tls_connection_info_t info;
    EXPECT(vireo_tls_connection_inspect(owner, &info, &error), VIREO_OK);
    CHECK(info.minimum_protocol_version == VIREO_TLS_CONTEXT_PROTOCOL_1_3);
    CHECK(info.maximum_protocol_version == VIREO_TLS_CONTEXT_PROTOCOL_1_3);
    CHECK(info.server_mode && info.fd_bound && !info.handshake_started && !info.handshake_complete);
    CHECK(info.wrapper_bytes == sizeof(*owner) && info.max_wrapper_bytes == 4096);
    CHECK(fcntl(pair[0], F_GETFL) == flags && fcntl(pair[0], F_GETFD) == descriptor_flags);
    peer_has_no_bytes(pair[1]);
    EXPECT(vireo_tls_connection_destroy(&owner, &error), VIREO_OK);
    CHECK(owner == NULL && error.stage == VIREO_TLS_CONNECTION_STAGE_NONE);
    CHECK(fcntl(pair[0], F_GETFL) == flags && fcntl(pair[0], F_GETFD) == descriptor_flags);
    CHECK(fd_count() == before);
    peer_has_no_bytes(pair[1]);
    EXPECT(vireo_tls_connection_destroy(&owner, NULL), VIREO_OK);
    close_pair(pair);
    EXPECT(vireo_tls_context_destroy(&context, NULL), VIREO_OK);
}

/** 两个独立SSL持native引用；结束原context包装和一个SSL不破坏另一个SSL。 */
static void context_reference_and_multiple_connections(void)
{
    vireo_tls_context_t *context = make_context();
    int first_pair[2]; make_pair(first_pair);
    int second_pair[2]; make_pair(second_pair);
    vireo_tls_connection_options_t options = {4096};
    vireo_tls_connection_t *first = NULL;
    vireo_tls_connection_t *second = NULL;
    EXPECT(vireo_tls_connection_create_server(context, &options, first_pair[0], &first, NULL), VIREO_OK);
    options.max_wrapper_bytes = 8192;
    EXPECT(vireo_tls_connection_create_server(context, &options, second_pair[0], &second, NULL), VIREO_OK);
    CHECK(first != second && first->native != second->native);
    SSL_CTX *native_context = SSL_get_SSL_CTX(first->native);
    CHECK(native_context == SSL_get_SSL_CTX(second->native));
    EXPECT(vireo_tls_context_destroy(&context, NULL), VIREO_OK);
    CHECK(context == NULL);
    CHECK(SSL_CTX_get0_certificate(native_context) != NULL);
    CHECK(SSL_CTX_get0_privatekey(native_context) != NULL);
    vireo_tls_connection_info_t info;
    EXPECT(vireo_tls_connection_inspect(first, &info, NULL), VIREO_OK);
    CHECK(info.max_wrapper_bytes == 4096);
    EXPECT(vireo_tls_connection_destroy(&first, NULL), VIREO_OK);
    CHECK(SSL_get_certificate(second->native) != NULL);
    CHECK(SSL_CTX_get0_certificate(SSL_get_SSL_CTX(second->native)) != NULL);
    EXPECT(vireo_tls_connection_inspect(second, &info, NULL), VIREO_OK);
    CHECK(info.max_wrapper_bytes == 8192);
    EXPECT(vireo_tls_connection_destroy(&second, NULL), VIREO_OK);
    peer_has_no_bytes(first_pair[1]); peer_has_no_bytes(second_pair[1]);
    close_pair(first_pair); close_pair(second_pair);
}

/** 纯参数拒绝保持owner及原库队列；非空owner用真实对象而非伪指针。 */
static void invalid_arguments_and_owner(void)
{
    vireo_tls_context_t *context = make_context();
    int pair[2]; make_pair(pair);
    vireo_tls_connection_options_t options = {4096};
    vireo_tls_connection_t *owner = NULL;
    vireo_tls_connection_error_t error;
    ERR_raise(ERR_LIB_USER, 123);
    unsigned long old_error = ERR_peek_error();
    EXPECT(vireo_tls_connection_create_server(NULL, &options, pair[0], &owner, &error), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tls_connection_create_server(context, NULL, pair[0], &owner, &error), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tls_connection_create_server(context, &options, -1, &owner, &error), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tls_connection_create_server(context, &options, pair[0], NULL, &error), VIREO_RESULT_INVALID_ARGUMENT);
    options.max_wrapper_bytes = 0;
    EXPECT(vireo_tls_connection_create_server(context, &options, pair[0], &owner, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == NULL && ERR_peek_error() == old_error);
    CHECK(error.stage == VIREO_TLS_CONNECTION_STAGE_NONE && error.system_errno == 0);
    CHECK(error.openssl_error_code == 0 && !error.has_more_errors);
    options.max_wrapper_bytes = 4096;
    EXPECT(vireo_tls_connection_create_server(context, &options, pair[0], &owner, NULL), VIREO_OK);
    CHECK(ERR_peek_error() == 0);
    vireo_tls_connection_t *original = owner;
    EXPECT(vireo_tls_connection_create_server(context, &options, pair[0], &owner, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == original);
    EXPECT(vireo_tls_connection_inspect(owner, NULL, &error), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_tls_connection_info_t info;
    memset(&info, 0xA5, sizeof(info));
    unsigned char original_info[sizeof(info)]; memcpy(original_info, &info, sizeof(info));
    EXPECT(vireo_tls_connection_inspect(NULL, &info, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(original_info, &info, sizeof(info)) == 0);
    EXPECT(vireo_tls_connection_destroy(NULL, &error), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tls_connection_destroy(&owner, NULL), VIREO_OK);
    close_pair(pair);
    EXPECT(vireo_tls_context_destroy(&context, NULL), VIREO_OK);
}

/** 硬上限只影响控制块预算，不按预算大小实际申请64MiB；sizeof仅用于own测试。 */
static void wrapper_budget_boundaries(void)
{
    vireo_tls_context_t *context = make_context();
    int pair[2]; make_pair(pair);
    size_t cases[] = {sizeof(vireo_tls_connection_t) - 1,
        VIREO_TLS_CONNECTION_MAX_WRAPPER_BYTES + 1, SIZE_MAX};
    vireo_tls_connection_t *owner = NULL;
    vireo_tls_connection_error_t error;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        vireo_tls_connection_options_t options = {cases[i]};
        ERR_clear_error(); ERR_raise(ERR_LIB_USER, 124);
        unsigned long old_error = ERR_peek_error();
        EXPECT(vireo_tls_connection_create_server(context, &options, pair[0], &owner, &error), VIREO_RESULT_RANGE);
        CHECK(owner == NULL && error.stage == VIREO_TLS_CONNECTION_STAGE_NONE);
        CHECK(ERR_peek_error() == old_error);
    }
    size_t success[] = {sizeof(vireo_tls_connection_t), VIREO_TLS_CONNECTION_MAX_WRAPPER_BYTES};
    for (size_t i = 0; i < sizeof(success) / sizeof(success[0]); ++i) {
        vireo_tls_connection_options_t options = {success[i]};
        EXPECT(vireo_tls_connection_create_server(context, &options, pair[0], &owner, &error), VIREO_OK);
        vireo_tls_connection_info_t info;
        EXPECT(vireo_tls_connection_inspect(owner, &info, NULL), VIREO_OK);
        CHECK(info.wrapper_bytes == sizeof(*owner) && info.max_wrapper_bytes == success[i]);
        EXPECT(vireo_tls_connection_destroy(&owner, NULL), VIREO_OK);
    }
    close_pair(pair);
    EXPECT(vireo_tls_context_destroy(&context, NULL), VIREO_OK);
}

/** 合法查询但flags/type不符不被静默修补；失败后由测试唯一拥有者关闭。 */
static void socket_shape_and_flags(void)
{
    vireo_tls_context_t *context = make_context();
    int types[] = {SOCK_STREAM | SOCK_CLOEXEC, SOCK_STREAM | SOCK_NONBLOCK,
        SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC};
    vireo_tls_connection_options_t options = {4096};
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); ++i) {
        int pair[2]; CHECK(socketpair(AF_UNIX, types[i], 0, pair) == 0);
        int flags = fcntl(pair[0], F_GETFL);
        int descriptor_flags = fcntl(pair[0], F_GETFD);
        vireo_tls_connection_t *owner = NULL;
        vireo_tls_connection_error_t error;
        EXPECT(vireo_tls_connection_create_server(context, &options, pair[0], &owner, &error), VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(owner == NULL && error.stage == VIREO_TLS_CONNECTION_STAGE_VALIDATE_FD);
        CHECK(error.system_errno == 0 && error.openssl_error_code == 0);
        CHECK(fcntl(pair[0], F_GETFL) == flags && fcntl(pair[0], F_GETFD) == descriptor_flags);
        close_pair(pair);
    }
    EXPECT(vireo_tls_context_destroy(&context, NULL), VIREO_OK);
}

/** 真实EBADF/ENOTSOCK/ENOTCONN分列，不以own故障代替原生错误证据。 */
static void native_query_failures(void)
{
    vireo_tls_context_t *context = make_context();
    vireo_tls_connection_options_t options = {4096};
    vireo_tls_connection_t *owner = NULL;
    vireo_tls_connection_error_t error;
    int pair[2]; make_pair(pair);
    int closed_fd = pair[0]; CHECK(close(closed_fd) == 0);
    ERR_raise(ERR_LIB_USER, 125);
    EXPECT(vireo_tls_connection_create_server(context, &options, closed_fd, &owner, &error), VIREO_RESULT_IO);
    CHECK(error.system_errno == EBADF && owner == NULL && ERR_peek_error() == 0);
    CHECK(error.stage == VIREO_TLS_CONNECTION_STAGE_VALIDATE_FD && error.openssl_error_code == 0);
    CHECK(close(pair[1]) == 0);
    int file = open("/dev/null", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    CHECK(file >= 0);
    EXPECT(vireo_tls_connection_create_server(context, &options, file, &owner, &error), VIREO_RESULT_IO);
    CHECK(error.system_errno == ENOTSOCK && owner == NULL);
    CHECK(fcntl(file, F_GETFD) != -1); CHECK(close(file) == 0);
    int unconnected = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(unconnected >= 0);
    EXPECT(vireo_tls_connection_create_server(context, &options, unconnected, &owner, &error), VIREO_RESULT_IO);
    CHECK(error.system_errno == ENOTCONN && owner == NULL);
    CHECK(close(unconnected) == 0);
    EXPECT(vireo_tls_context_destroy(&context, NULL), VIREO_OK);
}

/** own夹具串行使用；记录真实获取/释放次数，不把注入OOM冒系统耗尽。 */
typedef struct fault_state {
    size_t queries;        /**< 资格查询的实际回调数。 */
    size_t fail_query_at;  /**< 1..4对应四个只读资格查询，0不失败。 */
    int query_errno;       /**< 注入系统原因。 */
    size_t allocations;   /**< 包装申请次数。 */
    size_t deallocations; /**< 包装配对释放次数。 */
    size_t native_calls;  /**< SSL_new尝试次数。 */
    size_t bio_calls;     /**< BIO_new_socket尝试次数。 */
    bool fail_allocate;   /**< 包装申请返回NULL。 */
    bool fail_native;     /**< 原生SSL构造返回NULL。 */
    bool fail_bio;        /**< 原生BIO构造返回NULL。 */
    unsigned int errors; /**< 0无原因、1普通库原因、2普通后明确OOM。 */
    bool cleanup_error;   /**< deallocate时注入不应覆盖主诊断的次错。 */
    bool corrupt_native;  /**< 构造后破坏子SSL early-data策略以触发末端回滚。 */
} fault_state_t;

/** 明确模拟线程库队列，与真实native失败分列。 */
static void raise_fault(fault_state_t const *state)
{
    if (state->errors != 0) { ERR_raise(ERR_LIB_USER, 400); }
    if (state->errors == 2) { ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE); }
}

/** 真实申请但故意改变errno，覆盖成功外层恢复。 */
static void *fault_allocate(void *context, size_t bytes)
{
    fault_state_t *state = context;
    ++state->allocations;
    errno = ENOMEM;
    return state->fail_allocate ? NULL : malloc(bytes);
}

/** 真实释放并注入次错，覆盖主要诊断在清理之前已复制。 */
static void fault_deallocate(void *context, void *pointer)
{
    fault_state_t *state = context;
    ++state->deallocations;
    free(pointer);
    if (state->cleanup_error) { ERR_raise(ERR_LIB_USER, 999); }
    errno = EIO;
}

/** 每查询独立计数，使EINTR不重试和后续阶段未执行可被观测。 */
static bool query_fails(fault_state_t *state)
{
    ++state->queries;
    if (state->queries == state->fail_query_at) {
        errno = state->query_errno;
        return true;
    }
    return false;
}

/** 原生flags查询或指定步骤失败。 */
static int fault_get_flags(void *context, int fd, int command)
{
    return query_fails(context) ? -1 : fcntl(fd, command);
}

/** 原生类型查询或指定步骤失败，不发布失败输出。 */
static int fault_socket_type(void *context, int fd, int *out_type)
{
    if (query_fails(context)) { return -1; }
    socklen_t size = (socklen_t)sizeof(*out_type);
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, out_type, &size);
}

/** 原生peer资格查询或指定步骤失败，不取得任何新fd。 */
static int fault_peer_connected(void *context, int fd)
{
    if (query_fails(context)) { return -1; }
    struct sockaddr_storage peer;
    socklen_t size = (socklen_t)sizeof(peer);
    return getpeername(fd, (struct sockaddr *)&peer, &size);
}

/** 新SSL确实持给定context引用；early破坏只模拟本层末端防御路径。 */
static SSL *fault_create_native(void *context, SSL_CTX *native_context)
{
    fault_state_t *state = context;
    ++state->native_calls;
    if (state->fail_native) { raise_fault(state); return NULL; }
    SSL *native = SSL_new(native_context);
    CHECK(native != NULL);
    if (state->corrupt_native) { CHECK(SSL_set_max_early_data(native, 1) == 1); }
    return native;
}

/** 无论生产还是注入后的实际BIO，都保证NOCLOSE以免测试夹具引入错误关闭。 */
static BIO *fault_create_bio(void *context, int fd)
{
    fault_state_t *state = context;
    ++state->bio_calls;
    if (state->fail_bio) { raise_fault(state); return NULL; }
    return BIO_new_socket(fd, BIO_NOCLOSE);
}

/** 局部表可在创建后失效，context由本组测试保活至destroy。 */
static vireo_tls_connection_ops_t fault_ops(fault_state_t *state)
{
    vireo_tls_connection_ops_t ops = {state, fault_allocate, fault_deallocate,
        fault_get_flags, fault_socket_type, fault_peer_connected, fault_create_native,
        fault_create_bio};
    return ops;
}

/** 每个查询失败立即停止，不分配/调用SSL，EINTR没有隐式重试。 */
static void injected_query_failures(void)
{
    vireo_tls_context_t *context = make_context();
    int pair[2]; make_pair(pair);
    vireo_tls_connection_options_t options = {4096};
    int errors[] = {EINTR, EBADF, ENOTSOCK, ENOTCONN};
    for (size_t i = 1; i <= 4; ++i) {
        fault_state_t state = {0}; state.fail_query_at = i; state.query_errno = errors[i - 1];
        vireo_tls_connection_ops_t ops = fault_ops(&state);
        vireo_tls_connection_t *owner = NULL;
        vireo_tls_connection_error_t error;
        EXPECT(vireo_tls_connection_create_with_ops(context, &options, pair[0], &owner, &error, &ops), VIREO_RESULT_IO);
        CHECK(owner == NULL && error.system_errno == errors[i - 1]);
        CHECK(error.stage == VIREO_TLS_CONNECTION_STAGE_VALIDATE_FD && error.openssl_error_code == 0);
        CHECK(state.queries == i && state.allocations == 0 && state.native_calls == 0);
        CHECK(fcntl(pair[0], F_GETFD) != -1 && ERR_peek_error() == 0);
    }
    close_pair(pair);
    EXPECT(vireo_tls_context_destroy(&context, NULL), VIREO_OK);
}

/** 分别覆盖申请、SSL和BIO失败的配对释放及清理次错隔离。 */
static void injected_resource_failures(void)
{
    vireo_tls_context_t *context = make_context();
    int pair[2]; make_pair(pair);
    vireo_tls_connection_options_t options = {4096};
    for (unsigned int resource = 0; resource < 3; ++resource) {
        for (unsigned int errors = 0; errors < 3; ++errors) {
            fault_state_t state = {0};
            state.fail_allocate = resource == 0; state.fail_native = resource == 1;
            state.fail_bio = resource == 2; state.errors = errors; state.cleanup_error = true;
            vireo_tls_connection_ops_t ops = fault_ops(&state);
            vireo_tls_connection_t *owner = NULL;
            vireo_tls_connection_error_t error;
            EXPECT(vireo_tls_connection_create_with_ops(context, &options, pair[0], &owner, &error, &ops),
                resource == 0 || errors == 2 ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_INTERNAL);
            CHECK(owner == NULL && error.system_errno == 0);
            CHECK(error.stage == (resource == 0 ? VIREO_TLS_CONNECTION_STAGE_ALLOCATE_WRAPPER :
                (resource == 1 ? VIREO_TLS_CONNECTION_STAGE_CREATE_NATIVE : VIREO_TLS_CONNECTION_STAGE_BIND_FD)));
            CHECK(state.queries == 4 && state.allocations == 1);
            CHECK(state.deallocations == (resource == 0 ? 0U : 1U));
            CHECK(state.native_calls == (resource == 0 ? 0U : 1U));
            CHECK(state.bio_calls == (resource == 2 ? 1U : 0U));
            if (resource == 0 || errors == 0) {
                CHECK(error.openssl_error_code == 0 && !error.has_more_errors);
            } else {
                CHECK(ERR_GET_LIB((unsigned long)error.openssl_error_code) == ERR_LIB_USER);
                CHECK(ERR_GET_REASON((unsigned long)error.openssl_error_code) == 400);
                CHECK(error.has_more_errors == (errors == 2));
            }
            CHECK(ERR_peek_error() == 0 && fcntl(pair[0], F_GETFD) != -1);
            peer_has_no_bytes(pair[1]);
        }
    }
    close_pair(pair);
    EXPECT(vireo_tls_context_destroy(&context, NULL), VIREO_OK);
}

/** BIO已移交且native策略异常时仍逆序回滚；随后原context仍可创建正常连接。 */
static void late_initial_state_rollback(void)
{
    vireo_tls_context_t *context = make_context();
    int pair[2]; make_pair(pair);
    fault_state_t state = {0}; state.corrupt_native = true; state.cleanup_error = true;
    vireo_tls_connection_ops_t ops = fault_ops(&state);
    vireo_tls_connection_options_t options = {4096};
    vireo_tls_connection_t *owner = NULL;
    vireo_tls_connection_error_t error;
    EXPECT(vireo_tls_connection_create_with_ops(context, &options, pair[0], &owner, &error, &ops), VIREO_RESULT_INTERNAL);
    CHECK(owner == NULL && state.bio_calls == 1 && state.deallocations == 1);
    CHECK(error.stage == VIREO_TLS_CONNECTION_STAGE_INSPECT && error.openssl_error_code == 0);
    CHECK(ERR_peek_error() == 0); peer_has_no_bytes(pair[1]);
    EXPECT(vireo_tls_connection_create_server(context, &options, pair[0], &owner, NULL), VIREO_OK);
    EXPECT(vireo_tls_connection_destroy(&owner, NULL), VIREO_OK);
    close_pair(pair);
    EXPECT(vireo_tls_context_destroy(&context, NULL), VIREO_OK);
}

/** 缺回调在资格查询/申请前拒绝；成功对象保存操作表值而非局部表地址。 */
static void resource_table_and_value_copy(void)
{
    vireo_tls_context_t *context = make_context();
    int pair[2]; make_pair(pair);
    fault_state_t state = {0};
    vireo_tls_connection_options_t options = {4096};
    vireo_tls_connection_t *owner = NULL;
    EXPECT(vireo_tls_connection_create_with_ops(context, &options, pair[0], &owner, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    for (unsigned int i = 0; i < 7; ++i) {
        vireo_tls_connection_ops_t ops = fault_ops(&state);
        if (i == 0) { ops.allocate = NULL; }
        if (i == 1) { ops.deallocate = NULL; }
        if (i == 2) { ops.get_flags = NULL; }
        if (i == 3) { ops.socket_type = NULL; }
        if (i == 4) { ops.peer_connected = NULL; }
        if (i == 5) { ops.create_native = NULL; }
        if (i == 6) { ops.create_bio = NULL; }
        EXPECT(vireo_tls_connection_create_with_ops(context, &options, pair[0], &owner, NULL, &ops), VIREO_RESULT_INVALID_ARGUMENT);
    }
    CHECK(state.queries == 0 && state.allocations == 0);
    vireo_tls_connection_ops_t ops = fault_ops(&state);
    EXPECT(vireo_tls_connection_create_with_ops(context, &options, pair[0], &owner, NULL, &ops), VIREO_OK);
    memset(&ops, 0, sizeof(ops));
    EXPECT(vireo_tls_context_destroy(&context, NULL), VIREO_OK);
    EXPECT(vireo_tls_connection_destroy(&owner, NULL), VIREO_OK);
    CHECK(state.allocations == 1 && state.deallocations == 1 && state.native_calls == 1 && state.bio_calls == 1);
    close_pair(pair);
}

/** 原context配置异常时不取得本层资源；white-box破坏不冒真实库自行变异。 */
static void invalid_context_configuration(void)
{
    vireo_tls_context_t *context = make_context();
    int pair[2]; make_pair(pair);
    CHECK(SSL_CTX_set_max_early_data(context->native, 1) == 1);
    fault_state_t state = {0};
    vireo_tls_connection_ops_t ops = fault_ops(&state);
    vireo_tls_connection_options_t options = {4096};
    vireo_tls_connection_t *owner = NULL;
    vireo_tls_connection_error_t error;
    EXPECT(vireo_tls_connection_create_with_ops(context, &options, pair[0], &owner, &error, &ops), VIREO_RESULT_INTERNAL);
    CHECK(owner == NULL && state.queries == 4 && state.allocations == 0);
    CHECK(error.stage == VIREO_TLS_CONNECTION_STAGE_VALIDATE_CONTEXT && error.system_errno == 0);
    CHECK(error.openssl_error_code == 0 && !error.has_more_errors);
    CHECK(SSL_CTX_set_max_early_data(context->native, 0) == 1);
    close_pair(pair);
    EXPECT(vireo_tls_context_destroy(&context, NULL), VIREO_OK);
}

/** 每种native/包装不变量破坏后必须保持输出全部字节；恢复后再正常配对释放。 */
static void inspect_failure_preserves_all_bytes(void)
{
    vireo_tls_context_t *context = make_context();
    int pair[2]; make_pair(pair);
    vireo_tls_connection_options_t options = {4096};
    vireo_tls_connection_t *owner = NULL;
    EXPECT(vireo_tls_connection_create_server(context, &options, pair[0], &owner, NULL), VIREO_OK);
    for (unsigned int i = 0; i < 10; ++i) {
        SSL *native = owner->native;
        if (i == 0) { owner->native = NULL; }
        if (i == 1) { owner->borrowed_fd = -1; }
        if (i == 2) { owner->max_wrapper_bytes = 0; }
        if (i == 3) { CHECK(SSL_set_min_proto_version(native, TLS1_2_VERSION) == 1); }
        if (i == 4) { SSL_set_connect_state(native); }
        if (i == 5) { CHECK(SSL_set_max_early_data(native, 1) == 1); }
        if (i == 6) { CHECK(SSL_set_num_tickets(native, 1) == 1); }
        if (i == 7) { (void)SSL_clear_options(native, SSL_OP_NO_TICKET); }
        if (i == 8) { SSL_set_verify(native, SSL_VERIFY_PEER, NULL); }
        if (i == 9) { BIO_set_close(SSL_get_rbio(native), BIO_CLOSE); }
        vireo_tls_connection_info_t info;
        memset(&info, 0xA7, sizeof(info));
        unsigned char original[sizeof(info)]; memcpy(original, &info, sizeof(info));
        vireo_tls_connection_error_t error;
        EXPECT(vireo_tls_connection_inspect(owner, &info, &error), VIREO_RESULT_INTERNAL);
        CHECK(memcmp(original, &info, sizeof(info)) == 0);
        CHECK(error.stage == VIREO_TLS_CONNECTION_STAGE_INSPECT && error.system_errno == 0);
        owner->native = native; owner->borrowed_fd = pair[0]; owner->max_wrapper_bytes = 4096;
        CHECK(SSL_set_min_proto_version(native, TLS1_3_VERSION) == 1);
        SSL_set_accept_state(native);
        CHECK(SSL_set_max_early_data(native, 0) == 1);
        CHECK(SSL_set_num_tickets(native, 0) == 1);
        (void)SSL_set_options(native, SSL_OP_NO_TICKET);
        SSL_set_verify(native, SSL_VERIFY_NONE, NULL);
        BIO_set_close(SSL_get_rbio(native), BIO_NOCLOSE);
        EXPECT(vireo_tls_connection_inspect(owner, &info, NULL), VIREO_OK);
    }
    EXPECT(vireo_tls_connection_destroy(&owner, NULL), VIREO_OK);
    close_pair(pair);
    EXPECT(vireo_tls_context_destroy(&context, NULL), VIREO_OK);
}

/** 旧队列在基本拒绝/空销毁保持，真实操作清除；独立诊断不借用后续库队列。 */
static void error_queue_and_empty_destroy(void)
{
    vireo_tls_context_t *context = make_context();
    int pair[2]; make_pair(pair);
    vireo_tls_connection_options_t options = {4096};
    vireo_tls_connection_t *owner = NULL;
    vireo_tls_connection_error_t error;
    ERR_raise(ERR_LIB_USER, 130);
    unsigned long old_error = ERR_peek_error();
    EXPECT(vireo_tls_connection_destroy(NULL, &error), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tls_connection_destroy(&owner, &error), VIREO_OK);
    CHECK(ERR_peek_error() == old_error && error.stage == VIREO_TLS_CONNECTION_STAGE_NONE);
    EXPECT(vireo_tls_connection_create_server(context, &options, pair[0], &owner, &error), VIREO_OK);
    CHECK(ERR_peek_error() == 0);
    vireo_tls_connection_info_t info;
    ERR_raise(ERR_LIB_USER, 131);
    EXPECT(vireo_tls_connection_inspect(owner, &info, NULL), VIREO_OK);
    CHECK(ERR_peek_error() == 0);
    ERR_raise(ERR_LIB_USER, 132);
    EXPECT(vireo_tls_connection_destroy(&owner, &error), VIREO_OK);
    CHECK(ERR_peek_error() == 0);
    fault_state_t state = {0}; state.fail_native = true; state.errors = 2;
    vireo_tls_connection_ops_t ops = fault_ops(&state);
    EXPECT(vireo_tls_connection_create_with_ops(context, &options, pair[0], &owner, &error, &ops), VIREO_RESULT_NO_MEMORY);
    uint64_t saved_code = error.openssl_error_code;
    ERR_raise(ERR_LIB_USER, 133); ERR_clear_error();
    CHECK(error.openssl_error_code == saved_code && error.has_more_errors);
    close_pair(pair);
    EXPECT(vireo_tls_context_destroy(&context, NULL), VIREO_OK);
}

/** 只在重新exec后的进程处理fd0，避免违反fork后未exec的库使用前置条件。 */
static int fd_zero_case(void)
{
    vireo_tls_context_t *context = make_context();
    int result = close(STDIN_FILENO);
    CHECK(result == 0 || errno == EBADF);
    int pair[2]; make_pair(pair);
    CHECK(pair[0] == STDIN_FILENO);
    size_t before = fd_count();
    vireo_tls_connection_options_t options = {4096};
    vireo_tls_connection_t *owner = NULL;
    EXPECT(vireo_tls_connection_create_server(context, &options, 0, &owner, NULL), VIREO_OK);
    CHECK(SSL_get_fd(owner->native) == 0);
    EXPECT(vireo_tls_context_destroy(&context, NULL), VIREO_OK);
    vireo_tls_connection_info_t info;
    EXPECT(vireo_tls_connection_inspect(owner, &info, NULL), VIREO_OK);
    EXPECT(vireo_tls_connection_destroy(&owner, NULL), VIREO_OK);
    CHECK(fcntl(0, F_GETFD) != -1 && fd_count() == before);
    peer_has_no_bytes(pair[1]); close_pair(pair);
    (void)puts("fd zero exec case passed");
    return 0;
}

/** fork子进程只调用exec/_exit，父进程核退出状态且不依赖固定sleep。 */
static void fd_zero_after_exec(void)
{
    pid_t child = fork(); CHECK(child != -1);
    if (child == 0) {
        execl("/proc/self/exe", "vireo_tls_connection_test", "--fd-zero-case", (char *)NULL);
        _exit(127);
    }
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited == -1 && errno == EINTR);
    CHECK(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/** 每组有独立PASS，运行前后真实fd基线一致；不声明已执行网络握手。 */
int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--fd-zero-case") == 0) { return fd_zero_case(); }
    CHECK(argc == 1);
    size_t before = fd_count();
#define RUN(function) do { function(); (void)puts("[PASS] " #function); } while (0)
    RUN(lifecycle_and_no_network);
    RUN(context_reference_and_multiple_connections);
    RUN(invalid_arguments_and_owner);
    RUN(wrapper_budget_boundaries);
    RUN(socket_shape_and_flags);
    RUN(native_query_failures);
    RUN(injected_query_failures);
    RUN(injected_resource_failures);
    RUN(late_initial_state_rollback);
    RUN(resource_table_and_value_copy);
    RUN(invalid_context_configuration);
    RUN(inspect_failure_preserves_all_bytes);
    RUN(error_queue_and_empty_destroy);
    RUN(fd_zero_after_exec);
#undef RUN
    size_t after = fd_count(); CHECK(before == after);
    (void)printf("14 groups passed; fd %zu -> %zu\n", before, after);
    return 0;
}
