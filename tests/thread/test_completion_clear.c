/*
 * PROJECT : VIREO
 * FILE    : test_completion_clear.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : completion配对释放前全块观察及关闭/未交接结果的公开生命周期
 */
#include "completion_internal.h"

#include <vireo/thread/completion_queue.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "line %d: %s\n", __LINE__, #c); exit(1); } } while (0)
#define EXPECT(call, value) do { errno = EDOM; CHECK((call) == (value)); CHECK(errno == EDOM); } while (0)

/** context位于块外，只在对象存活且唯一owner销毁时观察。 */
typedef struct probe {
    void *live; /**< 当前真实活跃块，非额外owner。 */
    size_t bytes; /**< 精确申请长度。 */
    size_t attempts; /**< 包含失败的申请次数。 */
    size_t releases; /**< free前全零观察与配对释放次数。 */
    bool fail; /**< 局部失败注入，不影响其他实例。 */
} probe_t;

/** @brief 分配真实内存并预填非零以检测包括padding在内的漏清。 */
static void *allocate(void *context, size_t bytes) {
    probe_t *p = context;
    CHECK(p->live == NULL);
    ++p->attempts;
    p->bytes = bytes;
    if (p->fail) { return NULL; }
    p->live = malloc(bytes);
    CHECK(p->live != NULL);
    memset(p->live, 0xa5, bytes);
    errno = EILSEQ;
    return p->live;
}

/** @brief 只在真正free之前读取对象表示，避免释放后观察的未定义行为。 */
static void deallocate(void *context, void *allocation) {
    probe_t *p = context;
    CHECK(allocation == p->live && allocation != NULL);
    unsigned char const *bytes = allocation;
    for (size_t i = 0; i < p->bytes; ++i) { CHECK(bytes[i] == 0); }
    free(allocation);
    p->live = NULL;
    ++p->releases;
    errno = EILSEQ;
}

static vireo_completion_metadata_t metadata(void) {
    vireo_completion_metadata_t const value = {{{7, 0, 3, 11}, 42, 1, UINT64_MAX}, VIREO_OK, VIREO_STATUS_OK};
    return value;
}

/** @brief 销毁前短借确认响应仍完整，包含任意二进制而非仅字符串。 */
static void check_payload(vireo_completion_t const *completion, size_t length) {
    vireo_completion_payload_view_t view = {0};
    EXPECT(vireo_completion_borrow_payload(completion, &view), VIREO_OK);
    CHECK(view.size == length);
    CHECK(length != 0 || view.data == NULL);
    for (size_t i = 0; i < length; ++i) { CHECK(view.data[i] == (unsigned char)(i % 256)); }
}

static void direct_lifetimes(void) {
    size_t const lengths[] = {0, 1, 32, 4097, 1048576};
    for (size_t j = 0; j < sizeof(lengths) / sizeof(lengths[0]); ++j) {
        size_t const length = lengths[j];
        unsigned char *input = malloc(length + 1);
        CHECK(input != NULL);
        for (size_t i = 0; i < length + 1; ++i) { input[i] = (unsigned char)(i % 256); }
        probe_t p = {0};
        vireo_completion_allocator_t a = {&p, allocate, deallocate};
        vireo_completion_t *completion = NULL, *moved = NULL;
        EXPECT(vireo_completion_create_copy_with_allocator(metadata(), input, length,
            VIREO_COMPLETION_MAX_ALLOCATION_BYTES, &a, &completion), VIREO_OK);
        check_payload(completion, length);
        EXPECT(vireo_completion_move(&completion, &moved), VIREO_OK);
        CHECK(completion == NULL && p.releases == 0);
        check_payload(moved, length);
        a = (vireo_completion_allocator_t){0};
        EXPECT(vireo_completion_destroy(&moved), VIREO_OK);
        CHECK(moved == NULL && p.releases == 1 && p.live == NULL);
        EXPECT(vireo_completion_destroy(&moved), VIREO_OK);
        CHECK(p.releases == 1);
        for (size_t i = 0; i < length + 1; ++i) { CHECK(input[i] == (unsigned char)(i % 256)); }
        free(input);
    }
}

static void failures_preserve_owner(void) {
    probe_t p = {0};
    vireo_completion_allocator_t const a = {&p, allocate, deallocate};
    unsigned char input[] = {0, 1, 2};
    vireo_completion_t *completion = NULL;
    p.fail = true;
    EXPECT(vireo_completion_create_copy_with_allocator(metadata(), input, sizeof(input), 4096,
        &a, &completion), VIREO_RESULT_NO_MEMORY);
    CHECK(completion == NULL && p.attempts == 1 && p.releases == 0 && input[2] == 2);
    p.fail = false;
    EXPECT(vireo_completion_create_copy_with_allocator(metadata(), input, sizeof(input), 4096,
        &a, &completion), VIREO_OK);
    EXPECT(vireo_completion_create_copy(metadata(), input, sizeof(input), 4096, &completion), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_move(&completion, &completion), VIREO_RESULT_INVALID_ARGUMENT);
    check_payload(completion, sizeof(input));
    CHECK(p.releases == 0);
    EXPECT(vireo_completion_destroy(NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_destroy(&completion), VIREO_OK);
    CHECK(p.releases == 1);
}

static void closed_queue(void) {
    probe_t p = {0};
    vireo_completion_allocator_t const a = {&p, allocate, deallocate};
    unsigned char input[] = {0, 1, 2};
    vireo_completion_t *completion = NULL;
    EXPECT(vireo_completion_create_copy_with_allocator(metadata(), input, sizeof(input), 4096,
        &a, &completion), VIREO_OK);
    vireo_completion_queue_t *queue = NULL;
    vireo_completion_queue_options_t const options = {1, 65536};
    EXPECT(vireo_completion_queue_create(&options, &queue), VIREO_OK);
    vireo_completion_queue_transfer_report_t transfer = {0};
    EXPECT(vireo_completion_queue_try_push(queue, &completion, &transfer), VIREO_OK);
    CHECK(completion == NULL && transfer.transferred);
    vireo_completion_queue_close_report_t closed = {0};
    EXPECT(vireo_completion_queue_close(queue, &closed), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_RESULT_BUSY);
    CHECK(p.releases == 0); /* 关闭保留已发布响应，不能提前擦除。 */
    EXPECT(vireo_completion_queue_try_pop(queue, &completion, &transfer), VIREO_OK);
    check_payload(completion, sizeof(input));
    EXPECT(vireo_completion_destroy(&completion), VIREO_OK);
    CHECK(p.releases == 1);
    EXPECT(vireo_completion_create_copy_with_allocator(metadata(), input, sizeof(input), 4096,
        &a, &completion), VIREO_OK);
    EXPECT(vireo_completion_queue_try_push(queue, &completion, &transfer), VIREO_RESULT_CANCELLED);
    CHECK(completion != NULL && !transfer.transferred && p.releases == 1);
    check_payload(completion, sizeof(input));
    /* 未交接或迟到放弃结果均由最后owner销毁，不再借用响应。 */
    EXPECT(vireo_completion_destroy(&completion), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    CHECK(p.releases == 2);
}

int main(void) {
    direct_lifetimes();
    failures_preserve_owner();
    closed_queue();
    puts("completion clear: 5 sizes, move, failure retention and closed queue drain/rejection passed");
    return 0;
}
