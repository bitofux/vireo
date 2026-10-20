/*
- PROJECT : VIREO
- FILE    : test_tls_io_clear.c
- AUTHOR  : bitofux
- DATE    : 2026-10-19
- BRIEF   : 此模块负责：自有TLS暂存重试稳定、确认/终态擦除和释放前观察
 */
#include "tls_connection_internal.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
#define EXPECT(x, y) do { errno = ECHILD; CHECK((x) == (y)); CHECK(errno == ECHILD); } while (0)

typedef struct fixture {
    size_t allocations, fail_at, frees;
    bool prepared;
} fixture_t;
typedef struct script {
    int returned, classification, shutdown_result;
    size_t confirmed, calls;
    bool reject;
    uint8_t expected[32];
    size_t expected_size;
    void const *retry_pointer;
} script_t;
static void all_bytes(void const *pointer, size_t n, uint8_t value)
{
    uint8_t const *p = pointer;
    for (size_t i = 0; i < n; ++i) CHECK(p[i] == value);
}
static void *allocate(void *context, size_t size)
{
    fixture_t *f = context; CHECK(size == VIREO_TLS_IO_SCRATCH_BYTES);
    if (++f->allocations == f->fail_at) return NULL;
    void *p = malloc(size); CHECK(p != NULL); memset(p, 0xA5, size); return p;
}
static void deallocate(void *context, void *pointer)
{
    fixture_t *f = context;
    all_bytes(pointer, VIREO_TLS_IO_SCRATCH_BYTES, 0); ++f->frees; free(pointer);
}
static vireo_result_t buffer_create(void *context, size_t size, vireo_buffer_t **out)
{ (void)context; return vireo_buffer_create(size, out); }
static void buffer_destroy(void *context, vireo_buffer_t **out)
{ (void)context; CHECK(vireo_buffer_destroy(out) == VIREO_OK); }
static bool prepare(void *context, SSL *native)
{ CHECK(native != NULL); fixture_t *f = context; return f->prepared; }

/** 只模拟本层native结果，不冒充TLS握手；真实TLS集成由既有全量回归覆盖。 */
static void setup(vireo_tls_connection_t *c, fixture_t *f, vireo_result_t expected)
{
    *c = (vireo_tls_connection_t){.state = VIREO_TLS_HANDSHAKE_ESTABLISHED};
    SSL_CTX *ctx = SSL_CTX_new(TLS_method()); CHECK(ctx != NULL);
    c->native = SSL_new(ctx); CHECK(c->native != NULL); SSL_CTX_free(ctx);
    vireo_tls_io_options_t options = {32,32,32832,4,3,24,8,24};
    vireo_tls_io_config_ops_t ops = {f, allocate, deallocate, buffer_create, buffer_destroy, prepare};
    EXPECT(vireo_tls_connection_io_configure_with_ops(c, &options, NULL, &ops), expected);
}
static void teardown(vireo_tls_connection_t *c)
{ vireo_tls_io_release(&c->io); SSL_free(c->native); c->native = NULL; }
static int policy(void *context, bool *out)
{ script_t *s = context; *out = !s->reject; return 0; }
static int read_ex(void *context, SSL *native, void *data, size_t size, size_t *out)
{
    script_t *s = context; CHECK(native != NULL);
    if (s->retry_pointer != NULL) CHECK(s->retry_pointer == data);
    s->retry_pointer = data; ++s->calls;
    /* WANT也可改读工作区；活跃重试必须保留，不猜原生没有临时正文。 */
    memset(data, 0x61, size); *out = s->confirmed; errno = EPIPE; return s->returned;
}
static int write_ex(void *context, SSL *native, void const *data, size_t size, size_t *out)
{
    script_t *s = context; CHECK(native != NULL && size == s->expected_size);
    if (s->retry_pointer != NULL) CHECK(s->retry_pointer == data);
    CHECK(memcmp(data, s->expected, size) == 0);
    all_bytes((uint8_t const *)data + size, VIREO_TLS_IO_SCRATCH_BYTES - size, 0);
    s->retry_pointer = data; ++s->calls;
    *out = s->confirmed; errno = EPIPE; return s->returned;
}
static int get_error(void *context, SSL *native, int returned)
{ script_t *s = context; CHECK(native != NULL && returned == s->returned); return s->classification; }
static int shutdown_native(void *context, SSL *native)
{ script_t *s = context; CHECK(native != NULL); ++s->calls; return s->shutdown_result; }
static vireo_tls_io_ops_t ops(script_t *s)
{ vireo_tls_io_ops_t result = {s, policy, read_ex, write_ex, get_error}; return result; }
static void step(vireo_tls_connection_t *c, script_t *s, bool writing, size_t bytes, vireo_result_t expected)
{
    vireo_tls_io_budget_t budget = {bytes, 1}; vireo_tls_io_progress_t progress;
    vireo_tls_io_ops_t o = ops(s);
    EXPECT(vireo_tls_connection_io_with_ops(c, &budget, &progress, NULL, writing, &o), expected);
}
static void zero_scratch(vireo_tls_connection_t const *c)
{
    all_bytes(c->io.read_scratch, VIREO_TLS_IO_SCRATCH_BYTES, 0);
    all_bytes(c->io.write_scratch, VIREO_TLS_IO_SCRATCH_BYTES, 0);
}

/** WANT和可恢复拒绝保持整块内容，成功后清整块，后续短写不留长尾。 */
static void write_retry(void)
{
    fixture_t f = {.prepared = true}; vireo_tls_connection_t c; setup(&c, &f, VIREO_OK); zero_scratch(&c);
    uint8_t input[12]; memset(input, 0x73, sizeof(input));
    EXPECT(vireo_tls_connection_enqueue(&c, input, sizeof(input), NULL), VIREO_OK);
    script_t s = {.classification = SSL_ERROR_WANT_WRITE, .expected_size = sizeof(input)};
    memcpy(s.expected, input, sizeof(input)); step(&c, &s, true, 12, VIREO_OK);
    uint8_t snapshot[VIREO_TLS_IO_SCRATCH_BYTES]; memcpy(snapshot, c.io.write_scratch, sizeof(snapshot));
    step(&c, &s, true, 11, VIREO_RESULT_RANGE); CHECK(s.calls == 1);
    s.reject = true; step(&c, &s, true, 12, VIREO_RESULT_INVALID_ARGUMENT); CHECK(s.calls == 1);
    CHECK(memcmp(snapshot, c.io.write_scratch, sizeof(snapshot)) == 0);
    s.reject = false; s.returned = 1; s.confirmed = 12;
    step(&c, &s, true, 12, VIREO_OK); zero_scratch(&c);
    EXPECT(vireo_tls_connection_enqueue(&c, input, 2, NULL), VIREO_OK);
    s.expected_size = 2; s.confirmed = 2; s.retry_pointer = NULL;
    step(&c, &s, true, 2, VIREO_OK); zero_scratch(&c);
    all_bytes(input, sizeof(input), 0x73); teardown(&c); CHECK(f.frees == 2);
}

/** 短读确认先复制到FIFO再清暂存，EOF清读暂存且保留未消费尾部。 */
static void read_eof(void)
{
    fixture_t f = {.prepared = true}; vireo_tls_connection_t c; setup(&c, &f, VIREO_OK);
    script_t s = {.classification = SSL_ERROR_WANT_READ}; step(&c, &s, false, 12, VIREO_OK);
    all_bytes(c.io.read_scratch, 12, 0x61);
    s.returned = 1; s.confirmed = 3; step(&c, &s, false, 12, VIREO_OK); zero_scratch(&c);
    uint8_t const *p = NULL; size_t n = 0;
    EXPECT(vireo_tls_connection_read_peek(&c, &p, &n, NULL), VIREO_OK);
    CHECK(n == 3); all_bytes(p, n, 0x61);
    s.returned = 0; s.classification = SSL_ERROR_ZERO_RETURN; s.retry_pointer = NULL;
    step(&c, &s, false, 4, VIREO_OK); zero_scratch(&c);
    EXPECT(vireo_tls_connection_read_peek(&c, &p, &n, NULL), VIREO_OK); CHECK(n == 3);
    EXPECT(vireo_tls_connection_read_consume(&c, 3, NULL), VIREO_OK); teardown(&c);
}

/** fatal清另一方向仍在途的暂存，保留确认FIFO/首错，后续不再native。 */
static void fatal(void)
{
    fixture_t f = {.prepared = true}; vireo_tls_connection_t c; setup(&c, &f, VIREO_OK);
    script_t read = {.classification = SSL_ERROR_WANT_READ}; step(&c, &read, false, 8, VIREO_OK);
    uint8_t input[3] = {1,2,3}; EXPECT(vireo_tls_connection_enqueue(&c, input, 3, NULL), VIREO_OK);
    script_t s = {.classification = SSL_ERROR_SYSCALL, .expected_size = 3}; memcpy(s.expected, input, 3);
    step(&c, &s, true, 3, VIREO_RESULT_IO); zero_scratch(&c); CHECK(c.io.state == VIREO_TLS_IO_FAILED);
    step(&c, &s, true, 3, VIREO_RESULT_IO); CHECK(s.calls == 1);
    vireo_buffer_info_t info; CHECK(vireo_buffer_inspect(c.io.write_buffer, &info) == VIREO_OK);
    CHECK(info.readable_size == 3); teardown(&c);
}

/** close到期/原生关闭fatal/完成取消read WANT后清暂存，FIFO尾部不丢。 */
static void close_terminal(void)
{
    for (unsigned int mode = 0; mode < 3; ++mode) {
        fixture_t f = {.prepared = true}; vireo_tls_connection_t c; setup(&c, &f, VIREO_OK);
        script_t s = {.classification = SSL_ERROR_WANT_READ}; step(&c, &s, false, 8, VIREO_OK);
        uint8_t const tail[2] = {4,5}; CHECK(vireo_buffer_append(c.io.read_buffer, tail, 2) == VIREO_OK);
        EXPECT(vireo_tls_connection_close_request(&c, 1, 10, NULL), VIREO_OK);
        s.shutdown_result = mode == 1 ? -1 : 1; s.returned = -1; s.classification = SSL_ERROR_SYSCALL;
        vireo_tls_close_ops_t o = {ops(&s), shutdown_native}; vireo_tls_close_progress_t progress;
        EXPECT(vireo_tls_connection_close_with_ops(&c, mode == 0 ? 10 : 2, 8, &progress, NULL, &o),
            mode == 0 ? VIREO_RESULT_TIMEOUT : (mode == 1 ? VIREO_RESULT_IO : VIREO_OK));
        zero_scratch(&c);
        uint8_t const *p = NULL; size_t n = 0;
        EXPECT(vireo_tls_connection_read_peek(&c, &p, &n, NULL), VIREO_OK);
        CHECK(n == 2 && memcmp(p, tail, n) == 0); teardown(&c);
    }
}
static void release_and_rollback(void)
{
    for (size_t failed = 1; failed <= 3; ++failed) {
        fixture_t f = {.fail_at = failed < 3 ? failed : 0, .prepared = false};
        vireo_tls_connection_t c;
        setup(&c, &f, failed < 3 ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_INTERNAL);
        CHECK(c.io.state == VIREO_TLS_IO_DISABLED && f.frees == failed - 1); teardown(&c);
    }
    fixture_t f = {.prepared = true}; vireo_tls_connection_t c; setup(&c, &f, VIREO_OK);
    script_t s = {.classification = SSL_ERROR_WANT_READ}; step(&c, &s, false, 8, VIREO_OK);
    teardown(&c); CHECK(f.frees == 2); /* pending仍存在时destroy也须清整块再free。 */
}
int main(void)
{
    write_retry(); read_eof(); fatal(); close_terminal(); release_and_rollback();
    puts("TLS clear: retry/refusal/success/short/EOF/fatal, three close terminals, partial construction/release passed");
    return 0;
}
