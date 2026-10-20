#define _POSIX_C_SOURCE 200809L
#include "mysql_internal.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(call, want) do { errno = EDOM; assert((call) == (want)); assert(errno == EDOM); } while (0)
static size_t allocations;
static bool fail_alloc;
static bool fail_thread;
static bool fail_init;
static unsigned int fail_option;
static unsigned int option_count;
static bool block_connect;
static void *allocate(size_t size)
{
    errno = ENOMEM;
    if (fail_alloc) { return NULL; }
    void *p = malloc(size);
    if (p != NULL) { ++allocations; }
    return p;
}
static void release(void *p)
{
    assert(p != NULL && allocations > 0);
    --allocations;
    free(p);
    errno = EIO;
}
static bool thread_init(void) { return fail_thread || mysql_thread_init(); }
static MYSQL *native_init(MYSQL *p) { return fail_init ? NULL : mysql_init(p); }
static int options(MYSQL *n, enum mysql_option o, const void *v)
{
    ++option_count;
    return option_count == fail_option ? 1 : mysql_options(n, o, v);
}
static MYSQL *connect_native(MYSQL *n, const char *host, const char *user,
    const char *password, const char *db, unsigned int port, const char *socket,
    unsigned long flags)
{
    assert(strcmp(host, "localhost") == 0 && port == 0 && flags == 0);
    if (block_connect) { return NULL; }
    return mysql_real_connect(n, host, user, password, db, port, socket, flags);
}
static int bad_library(int argc, char **argv, char **groups)
{
    assert(argc == 0 && argv == NULL && groups == NULL);
    return 1;
}
static int bad_signal(int sig, const struct sigaction *in, struct sigaction *out)
{
    assert(sig == SIGPIPE && in == NULL && out != NULL);
    errno = EACCES;
    return -1;
}
static vireo_mysql_connection_options_t base_options(void)
{
    return (vireo_mysql_connection_options_t){"/absent/vireo.sock", "vireo", "", "db", 1, 1, 1};
}
static void expect_open(vireo_mysql_thread_t *t,
    const vireo_mysql_connection_options_t *o, vireo_result_t expected,
    vireo_mysql_stage_t stage)
{
    vireo_mysql_connection_t *c = NULL;
    vireo_mysql_error_t e;
    memset(&e, 0x55, sizeof(e));
    CHECK(vireo_mysql_connection_open(t, o, &c, &e), expected);
    assert(c == NULL && e.stage == stage && e.system_error == 0);
    assert(e.mysql_code == 0 && e.sqlstate[0] == '\0');
}
static void boundaries(vireo_mysql_thread_t *t)
{
    vireo_mysql_connection_options_t o = base_options();
    const size_t limits[] = {107, 128, 1024, 256};
    char storage[1026];
    block_connect = true;
    for (size_t i = 0; i < 4; ++i) {
        for (unsigned int kind = 0; kind < 5; ++kind) {
            o = base_options();
            const char **fields[] = {&o.unix_socket, &o.username, &o.password, &o.database};
            memset(storage, 'x', sizeof(storage));
            size_t length = kind == 2 ? 1 : kind == 3 ? limits[i] : limits[i] + 1;
            storage[0] = i == 0 ? '/' : 'x';
            storage[length] = '\0';
            *fields[i] = kind == 0 ? NULL : kind == 1 ? "" : storage;
            if (kind == 0 || (kind == 1 && i != 2)) {
                expect_open(t, &o, VIREO_RESULT_INVALID_ARGUMENT, VIREO_MYSQL_STAGE_NONE);
            } else if (kind == 4) {
                expect_open(t, &o, VIREO_RESULT_RANGE, VIREO_MYSQL_STAGE_NONE);
            } else {
                expect_open(t, &o, VIREO_RESULT_DATABASE, VIREO_MYSQL_STAGE_CONNECT);
            }
        }
    }
    /* 无NUL的上限+1字节数组，在ASan下证明有界扫描不越界。 */
    for (size_t i = 0; i < 4; ++i) {
        char *p = malloc(limits[i] + 1);
        assert(p != NULL);
        memset(p, 'x', limits[i] + 1);
        p[0] = '/'; o = base_options();
        const char **fields[] = {&o.unix_socket, &o.username, &o.password, &o.database};
        *fields[i] = p;
        expect_open(t, &o, VIREO_RESULT_RANGE, VIREO_MYSQL_STAGE_NONE);
        free(p);
    }
    o = base_options(); o.unix_socket = "relative";
    expect_open(t, &o, VIREO_RESULT_INVALID_ARGUMENT, VIREO_MYSQL_STAGE_NONE);
    for (size_t i = 0; i < 3; ++i) {
        uint32_t values[] = {0, 1, 3600, 3601, UINT32_MAX};
        for (size_t j = 0; j < 5; ++j) {
            o = base_options();
            uint32_t *fields[] = {&o.connect_timeout_seconds, &o.read_timeout_seconds, &o.write_timeout_seconds};
            *fields[i] = values[j];
            expect_open(t, &o, j == 0 ? VIREO_RESULT_INVALID_ARGUMENT :
                j > 2 ? VIREO_RESULT_RANGE : VIREO_RESULT_DATABASE,
                j == 1 || j == 2 ? VIREO_MYSQL_STAGE_CONNECT : VIREO_MYSQL_STAGE_NONE);
        }
    }
    block_connect = false;
}
typedef struct wrong_thread_args {
    vireo_mysql_runtime_t *runtime;
    vireo_mysql_thread_t *guard;
} wrong_thread_args_t;
static void *wrong_thread(void *argument)
{
    wrong_thread_args_t *a = argument;
    vireo_mysql_thread_t *borrow = a->guard;
    vireo_mysql_runtime_t *root_borrow = a->runtime;
    vireo_mysql_connection_info_t info = {123, 456};
    vireo_mysql_connection_options_t o = base_options();
    expect_open(borrow, &o, VIREO_RESULT_INVALID_ARGUMENT, VIREO_MYSQL_STAGE_NONE);
    CHECK(vireo_mysql_thread_detach(&borrow), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_runtime_destroy(&root_borrow), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_connection_inspect(borrow, NULL, &info), VIREO_RESULT_INVALID_ARGUMENT);
    assert(info.server_version == 123 && info.connection_id == 456);
    assert(borrow == a->guard && root_borrow == a->runtime);
    vireo_mysql_thread_t *own = NULL;
    CHECK(vireo_mysql_thread_attach(a->runtime, &own, NULL), VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&own), VIREO_OK);
    return NULL;
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    struct sigaction action = {0};
    action.sa_handler = SIG_IGN;
    assert(sigemptyset(&action.sa_mask) == 0);
    assert(sigaction(SIGPIPE, &action, NULL) == 0);
    vireo_mysql_ops_t ops = vireo_mysql_native_ops;
    ops.allocate = allocate; ops.release = release;
    ops.thread_init = thread_init; ops.init = native_init;
    ops.options = options; ops.connect = connect_native;
    vireo_mysql_runtime_t *r = NULL;
    vireo_mysql_error_t e;
    if (strcmp(argv[1], "library_failure") == 0) {
        ops.library_init = bad_library;
        CHECK(vireo_mysql_runtime_create_with_ops(&r, &e, &ops), VIREO_RESULT_DATABASE);
        assert(r == NULL && allocations == 0 && e.stage == VIREO_MYSQL_STAGE_LIBRARY_INIT);
        CHECK(vireo_mysql_runtime_create(&r, &e), VIREO_RESULT_CANCELLED);
        puts("PASS terminal library failure"); return 0;
    }
    assert(strcmp(argv[1], "resources") == 0);
    CHECK(vireo_mysql_runtime_create(NULL, &e), VIREO_RESULT_INVALID_ARGUMENT);
    assert(e.stage == VIREO_MYSQL_STAGE_NONE);
    action.sa_handler = SIG_DFL; assert(sigaction(SIGPIPE, &action, NULL) == 0);
    CHECK(vireo_mysql_runtime_create(&r, &e), VIREO_RESULT_INVALID_ARGUMENT);
    assert(e.stage == VIREO_MYSQL_STAGE_SIGNAL_POLICY && r == NULL);
    struct sigaction observed;
    assert(sigaction(SIGPIPE, NULL, &observed) == 0 && observed.sa_handler == SIG_DFL);
    action.sa_handler = SIG_IGN; assert(sigaction(SIGPIPE, &action, NULL) == 0);
    ops.signal_read = bad_signal;
    CHECK(vireo_mysql_runtime_create_with_ops(&r, &e, &ops), VIREO_RESULT_IO);
    assert(e.system_error == EACCES && e.stage == VIREO_MYSQL_STAGE_SIGNAL_POLICY);
    ops.signal_read = sigaction;
    fail_alloc = true;
    CHECK(vireo_mysql_runtime_create_with_ops(&r, &e, &ops), VIREO_RESULT_NO_MEMORY);
    assert(r == NULL && allocations == 0 && e.stage == VIREO_MYSQL_STAGE_ALLOCATE);
    fail_alloc = false;
    CHECK(vireo_mysql_runtime_create_with_ops(&r, &e, &ops), VIREO_OK);
    assert(e.stage == VIREO_MYSQL_STAGE_NONE && allocations == 1);
    CHECK(vireo_mysql_runtime_create(&r, &e), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_mysql_runtime_t *second = NULL;
    CHECK(vireo_mysql_runtime_create(&second, NULL), VIREO_RESULT_BUSY);
    CHECK(vireo_mysql_runtime_destroy(NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_runtime_destroy(&second), VIREO_OK);
    vireo_mysql_thread_t *t = NULL, *duplicate = NULL;
    CHECK(vireo_mysql_thread_attach(NULL, &t, &e), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_thread_attach(r, NULL, &e), VIREO_RESULT_INVALID_ARGUMENT);
    atomic_store(&r->guards, SIZE_MAX);
    CHECK(vireo_mysql_thread_attach(r, &t, &e), VIREO_RESULT_OVERFLOW);
    atomic_store(&r->guards, 0);
    fail_alloc = true;
    CHECK(vireo_mysql_thread_attach(r, &t, &e), VIREO_RESULT_NO_MEMORY);
    fail_alloc = false; fail_thread = true;
    CHECK(vireo_mysql_thread_attach(r, &t, &e), VIREO_RESULT_DATABASE);
    assert(e.stage == VIREO_MYSQL_STAGE_THREAD_INIT && atomic_load(&r->guards) == 0 && allocations == 1);
    fail_thread = false;
    CHECK(vireo_mysql_thread_attach(r, &t, &e), VIREO_OK);
    CHECK(vireo_mysql_thread_attach(r, &t, &e), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_thread_attach(r, &duplicate, NULL), VIREO_RESULT_BUSY);
    CHECK(vireo_mysql_runtime_destroy(&r), VIREO_RESULT_BUSY);
    CHECK(vireo_mysql_thread_detach(NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_thread_detach(&duplicate), VIREO_OK);
    pthread_t worker;
    wrong_thread_args_t args = {r, t};
    assert(pthread_create(&worker, NULL, wrong_thread, &args) == 0);
    assert(pthread_join(worker, NULL) == 0);
    vireo_mysql_connection_t *c = NULL;
    vireo_mysql_connection_options_t o = base_options();
    CHECK(vireo_mysql_connection_open(t, &o, NULL, &e), VIREO_RESULT_INVALID_ARGUMENT);
    expect_open(NULL, &o, VIREO_RESULT_INVALID_ARGUMENT, VIREO_MYSQL_STAGE_NONE);
    expect_open(t, NULL, VIREO_RESULT_INVALID_ARGUMENT, VIREO_MYSQL_STAGE_NONE);
    /* 非空owner校验优先，不将borrow送入open。 */
    vireo_mysql_connection_t placeholder = {0}; c = &placeholder;
    CHECK(vireo_mysql_connection_open(t, &o, &c, &e), VIREO_RESULT_INVALID_ARGUMENT);
    assert(c == &placeholder); c = NULL;
    boundaries(t);
    atomic_store(&r->connections, SIZE_MAX);
    expect_open(t, &o, VIREO_RESULT_OVERFLOW, VIREO_MYSQL_STAGE_NONE);
    atomic_store(&r->connections, 0);
    fail_alloc = true;
    expect_open(t, &o, VIREO_RESULT_NO_MEMORY, VIREO_MYSQL_STAGE_ALLOCATE);
    fail_alloc = false; fail_init = true;
    expect_open(t, &o, VIREO_RESULT_NO_MEMORY, VIREO_MYSQL_STAGE_NATIVE_INIT);
    fail_init = false;
    for (unsigned int i = 1; i <= 6; ++i) {
        fail_option = i; option_count = 0;
        expect_open(t, &o, VIREO_RESULT_DATABASE, VIREO_MYSQL_STAGE_OPTIONS);
        assert(allocations == 2 && atomic_load(&r->connections) == 0);
    }
    fail_option = 0; block_connect = true;
    expect_open(t, &o, VIREO_RESULT_DATABASE, VIREO_MYSQL_STAGE_CONNECT);
    vireo_mysql_connection_info_t info = {123, 456};
    CHECK(vireo_mysql_connection_inspect(t, NULL, &info), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_connection_inspect(t, &placeholder, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_mysql_runtime_t unrelated = {0};
    placeholder.runtime = &unrelated;
    CHECK(vireo_mysql_connection_inspect(t, &placeholder, &info), VIREO_RESULT_INVALID_ARGUMENT);
    assert(info.server_version == 123 && info.connection_id == 456);
    c = &placeholder;
    CHECK(vireo_mysql_connection_destroy(t, &c), VIREO_RESULT_INVALID_ARGUMENT);
    assert(c == &placeholder); c = NULL;
    CHECK(vireo_mysql_connection_destroy(NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_connection_destroy(NULL, &c), VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&t), VIREO_OK);
    assert(allocations == 1 && atomic_load(&r->guards) == 0 && atomic_load(&r->connections) == 0);
    CHECK(vireo_mysql_runtime_destroy(&r), VIREO_OK);
    assert(r == NULL && allocations == 0);
    CHECK(vireo_mysql_runtime_destroy(&r), VIREO_OK);
    CHECK(vireo_mysql_runtime_create(&r, &e), VIREO_RESULT_CANCELLED);
    puts("PASS lifecycle, bounds, errno, ownership, checked counters and injected cleanup");
    return 0;
}
