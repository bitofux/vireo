/*
- PROJECT : VIREO
- FILE    : test_buffer_clear.c
- AUTHOR  : bitofux
- DATE    : 2026-10-19
- BRIEF   : 此模块负责：生命周期字节区、重叠整理及真实free前整块擦除观察
 */
#include "base/buffer_internal.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
#define OK(x) do { errno = ECHILD; CHECK((x) == VIREO_OK); CHECK(errno == ECHILD); } while (0)

typedef struct block { void *pointer; size_t size; } block_t;
typedef struct fixture {
    block_t blocks[3]; /**< 只在真实free前读活跃分配，不依赖buffer私有布局。 */
    size_t calls, fail_at, freed;
    uint8_t *data; /**< 第二次分配的活跃字节区，仅分配器观测用。 */
} fixture_t;

static void bytes_equal(void const *p, size_t n, uint8_t value)
{
    uint8_t const *bytes = p;
    for (size_t i = 0; i < n; ++i) CHECK(bytes[i] == value);
}
static void *allocate(void *context, size_t size)
{
    fixture_t *f = context;
    if (++f->calls == f->fail_at) return NULL;
    void *p = malloc(size); CHECK(p != NULL); memset(p, 0xA5, size);
    for (size_t i = 0; i < 3; ++i) if (f->blocks[i].pointer == NULL) {
        f->blocks[i] = (block_t){p, size};
        if (f->calls >= 2) f->data = p;
        errno = ENOMEM; return p;
    }
    abort();
}
static void deallocate(void *context, void *pointer)
{
    fixture_t *f = context;
    for (size_t i = 0; i < 3; ++i) if (f->blocks[i].pointer == pointer) {
        bytes_equal(pointer, f->blocks[i].size, 0);
        f->blocks[i] = (block_t){0}; ++f->freed;
        free(pointer); errno = ENOTTY; return;
    }
    abort();
}
static vireo_buffer_t *create(fixture_t *f, size_t capacity)
{
    vireo_buffer_allocator_t a = {f, allocate, deallocate};
    vireo_buffer_t *b = NULL;
    OK(vireo_buffer_create_with_allocator(capacity, &a, &b)); return b;
}
static void view_equals(vireo_buffer_t *b, uint8_t const *expected, size_t size)
{
    uint8_t const *p = NULL; size_t n = SIZE_MAX;
    OK(vireo_buffer_peek(b, &p, &n)); CHECK(n == size);
    if (size != 0) CHECK(memcmp(p, expected, size) == 0); else CHECK(p == NULL);
}

/** 多个r覆盖源/目标重叠、不重叠及全空，未用容量仍保留allocator填充值。 */
static void consume_compact(void)
{
    uint8_t const input[] = {1,2,3,4,5,6,7,8};
    for (size_t take = 0; take <= sizeof(input); ++take) {
        fixture_t f = {0}; vireo_buffer_t *b = create(&f, 16);
        OK(vireo_buffer_append(b, input, sizeof(input)));
        uint8_t snapshot[16]; memcpy(snapshot, f.data, sizeof(snapshot));
        CHECK(vireo_buffer_consume(b, 9) == VIREO_RESULT_RANGE);
        CHECK(memcmp(snapshot, f.data, sizeof(snapshot)) == 0);
        OK(vireo_buffer_consume(b, take));
        bytes_equal(f.data, take, 0);
        CHECK(memcmp(f.data + take, input + take, sizeof(input) - take) == 0);
        OK(vireo_buffer_compact(b));
        view_equals(b, input + take, sizeof(input) - take);
        bytes_equal(f.data + sizeof(input) - take, take, 0);
        bytes_equal(f.data + sizeof(input), 8, 0xA5);
        OK(vireo_buffer_compact(b)); OK(vireo_buffer_consume(b, 0));
        OK(vireo_buffer_destroy(&b)); CHECK(b == NULL && f.freed == 2);
        CHECK(memcmp(input, (uint8_t[]){1,2,3,4,5,6,7,8}, sizeof(input)) == 0);
    }
}

/** 分配失败保持原区每个字节和view，成功换区只复制未读区且旧块整块为零。 */
static void storage(void)
{
    fixture_t f = {0}; vireo_buffer_t *b = create(&f, 16);
    uint8_t const input[] = {11,12,13,14,15,16,17,18};
    OK(vireo_buffer_append(b, input, sizeof(input))); OK(vireo_buffer_consume(b, 3));
    uint8_t snapshot[16]; memcpy(snapshot, f.data, sizeof(snapshot));
    uint8_t const *p = NULL, *after = NULL; size_t n = 0, count = 0;
    OK(vireo_buffer_peek(b, &p, &n)); f.fail_at = f.calls + 1;
    CHECK(vireo_buffer_reserve(b, 32) == VIREO_RESULT_NO_MEMORY);
    CHECK(memcmp(snapshot, f.data, sizeof(snapshot)) == 0);
    OK(vireo_buffer_peek(b, &after, &count)); CHECK(p == after && n == count);
    f.fail_at = f.calls + 1;
    CHECK(vireo_buffer_shrink(b, 7) == VIREO_RESULT_NO_MEMORY);
    CHECK(memcmp(snapshot, f.data, sizeof(snapshot)) == 0);
    f.fail_at = 0; OK(vireo_buffer_reserve(b, 32)); CHECK(f.freed == 1);
    view_equals(b, input + 3, 5); bytes_equal(f.data + 5, 32, 0xA5);
    OK(vireo_buffer_shrink(b, 5)); CHECK(f.freed == 2);
    view_equals(b, input + 3, 5); OK(vireo_buffer_consume(b, 5));
    bytes_equal(f.data, 5, 0); OK(vireo_buffer_destroy(&b)); CHECK(f.freed == 4);
}

/** reserve走原地compact、同容量shrink空操作、空区换区及创建第二步失败。 */
static void rollback_reuse(void)
{
    fixture_t f = {0}; vireo_buffer_t *b = create(&f, 8);
    uint8_t input[8]; memset(input, 0x53, sizeof(input));
    OK(vireo_buffer_append(b, input, sizeof(input))); OK(vireo_buffer_consume(b, 5));
    OK(vireo_buffer_reserve(b, 4)); CHECK(f.calls == 2);
    bytes_equal(f.data, 3, 0x53); bytes_equal(f.data + 3, 5, 0);
    OK(vireo_buffer_shrink(b, 8)); OK(vireo_buffer_consume(b, 3));
    OK(vireo_buffer_shrink(b, 1)); OK(vireo_buffer_destroy(&b));
    fixture_t bad = {.fail_at = 2}; vireo_buffer_allocator_t a = {&bad, allocate, deallocate};
    CHECK(vireo_buffer_create_with_allocator(8, &a, &b) == VIREO_RESULT_NO_MEMORY);
    CHECK(b == NULL && bad.freed == 1);
    OK(vireo_buffer_destroy(&b)); CHECK(vireo_buffer_destroy(NULL) == VIREO_RESULT_INVALID_ARGUMENT);
}
int main(void)
{
    consume_compact(); storage(); rollback_reuse();
    puts("buffer clear: 9 interval cases, storage rollback/replacement, reuse and partial construction passed");
    return 0;
}
