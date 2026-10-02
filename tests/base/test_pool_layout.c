/*
 * PROJECT : VIREO
 * FILE    : test_pool_layout.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-02
 * BRIEF   : 此模块负责：
 * -- 验证槽位布局、预算、非法输入与算术极限
 * -- 通过字节哨兵和独立小域 oracle 检验失败保持及步长最小性
 */

#include <vireo/base/pool.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

/**
 * @brief 检验明确输入的五字段布局和成功时 errno 保持
 * @param[in] size 正对象字节数。
 * @param[in] alignment 正二次幂对齐单位。
 * @param[in] count 正槽位数量。
 * @param[in] budget 正槽位字节预算。
 * @param[in] stride 独立预期槽位步长。
 * @param[in] bytes 独立预期存储字节数。
 * @return 0 表示断言成立，1 表示失败，交由测试入口传播。
 * @note 输出为局部值，无资源或所有权转移；故意设置 errno 哨兵。
 */
static int expect_layout(size_t size, size_t alignment, size_t count,
                         size_t budget, size_t stride, size_t bytes) {
    vireo_pool_layout_t layout = {0};
    errno = EDOM;
    CHECK(vireo_pool_layout_compute(size, alignment, count, budget, &layout) == VIREO_OK);
    CHECK(errno == EDOM);
    CHECK(layout.element_size == size);
    CHECK(layout.element_alignment == alignment);
    CHECK(layout.capacity == count);
    CHECK(layout.slot_stride == stride);
    CHECK(layout.storage_bytes == bytes);
    return 0;
}

/**
 * @brief 检验错误分类、errno 和整个输出对象（含 padding）保持
 * @param[in] size 被测对象字节数，可非法。
 * @param[in] alignment 被测对齐单位，可非法。
 * @param[in] count 被测槽位数量，可非法。
 * @param[in] budget 被测字节预算，可非法。
 * @param[in] expected 明确预期的失败结果。
 * @return 0 表示全部断言成立，1 表示失败。
 * @note 局部输出用 memset 初始化所有字节，失败前后只按字节比较，
 *     不读取哨兵构造的字段值；无资源转移。
 */
static int expect_failure(size_t size, size_t alignment, size_t count,
                          size_t budget, vireo_result_t expected) {
    vireo_pool_layout_t layout;
    unsigned char before[sizeof(layout)];
    memset(&layout, 0xA5, sizeof(layout));
    memcpy(before, &layout, sizeof(layout));
    errno = EACCES;
    CHECK(vireo_pool_layout_compute(size, alignment, count, budget, &layout) == expected);
    CHECK(errno == EACCES);
    CHECK(memcmp(before, &layout, sizeof(layout)) == 0);
    return 0;
}

static int test_unaligned_size(void) {
    CHECK(expect_layout(13, 8, 3, 48, 16, 48) == 0);
    CHECK(expect_layout(3, 16, 2, 32, 16, 32) == 0);
    return 0;
}

static int test_already_aligned(void) {
    CHECK(expect_layout(16, 8, 4, 64, 16, 64) == 0);
    CHECK(expect_layout(8, 8, 1, 8, 8, 8) == 0);
    return 0;
}

static int test_minimum(void) {
    CHECK(expect_layout(1, 1, 1, 1, 1, 1) == 0);
    CHECK(expect_layout(7, 1, 3, 21, 7, 21) == 0);
    return 0;
}

static int test_c_type(void) {
    struct sample_object {
        unsigned char kind;
        uint64_t sequence;
    };
    size_t size = sizeof(struct sample_object);
    size_t alignment = _Alignof(struct sample_object);
    CHECK(expect_layout(size, alignment, 1, size, size, size) == 0);
    return 0;
}

static int test_invalid_arguments(void) {
    CHECK(expect_failure(0, 8, 3, 48, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    CHECK(expect_failure(13, 0, 3, 48, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    CHECK(expect_failure(13, 8, 0, 48, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    CHECK(expect_failure(13, 8, 3, 0, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    CHECK(expect_failure(13, 3, 3, 48, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    CHECK(expect_failure(13, 6, 3, 48, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    CHECK(expect_failure(1, SIZE_MAX, 1, SIZE_MAX, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    /* 参数错误优先，即使其他输入足以触发溢出。 */
    CHECK(expect_failure(SIZE_MAX, 2, SIZE_MAX, 0, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    errno = EIO;
    CHECK(vireo_pool_layout_compute(13, 8, 3, 48, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EIO);
    return 0;
}

static int test_budget(void) {
    CHECK(expect_layout(13, 8, 3, 49, 16, 48) == 0);
    CHECK(expect_layout(13, 8, 3, 48, 16, 48) == 0);
    CHECK(expect_failure(13, 8, 3, 47, VIREO_RESULT_RANGE) == 0);
    /* 13 * 3 = 39 忽略填充，不能作为三个完整槽位的预算。 */
    CHECK(expect_failure(13, 8, 3, 39, VIREO_RESULT_RANGE) == 0);
    CHECK(expect_failure(1, 8, 1, 1, VIREO_RESULT_RANGE) == 0);
    return 0;
}

static int test_alignment_overflow(void) {
    CHECK(expect_failure(SIZE_MAX, 2, 1, SIZE_MAX, VIREO_RESULT_OVERFLOW) == 0);
    CHECK(expect_failure(SIZE_MAX, 2, 1, 1, VIREO_RESULT_OVERFLOW) == 0);
    size_t highest_power = SIZE_MAX / 2 + 1;
    CHECK(expect_failure(highest_power + 1, highest_power, 1,
                         SIZE_MAX, VIREO_RESULT_OVERFLOW) == 0);
    CHECK(expect_layout(SIZE_MAX - 1, 2, 1, SIZE_MAX,
                        SIZE_MAX - 1, SIZE_MAX - 1) == 0);
    return 0;
}

static int test_multiplication_overflow(void) {
    CHECK(expect_layout(SIZE_MAX / 2, 1, 2, SIZE_MAX,
                        SIZE_MAX / 2, SIZE_MAX - 1) == 0);
    CHECK(expect_failure(SIZE_MAX / 2 + 1, 1, 2,
                         SIZE_MAX, VIREO_RESULT_OVERFLOW) == 0);
    CHECK(expect_failure(SIZE_MAX / 2 + 1, 1, 2, 1, VIREO_RESULT_OVERFLOW) == 0);
    CHECK(expect_failure(1, SIZE_MAX / 2 + 1, 2,
                         SIZE_MAX, VIREO_RESULT_OVERFLOW) == 0);
    return 0;
}

static int test_maximum_values(void) {
    CHECK(expect_layout(SIZE_MAX, 1, 1, SIZE_MAX, SIZE_MAX, SIZE_MAX) == 0);
    CHECK(expect_layout(1, 1, SIZE_MAX, SIZE_MAX, 1, SIZE_MAX) == 0);
    size_t highest_power = SIZE_MAX / 2 + 1;
    CHECK(expect_layout(1, highest_power, 1, highest_power,
                        highest_power, highest_power) == 0);
    return 0;
}

static int test_repeated_output(void) {
    vireo_pool_layout_t layout = {0};
    CHECK(vireo_pool_layout_compute(13, 8, 3, 48, &layout) == VIREO_OK);
    unsigned char before[sizeof(layout)];
    memcpy(before, &layout, sizeof(layout));
    CHECK(vireo_pool_layout_compute(13, 8, 3, 47, &layout) == VIREO_RESULT_RANGE);
    CHECK(memcmp(before, &layout, sizeof(layout)) == 0);
    /* 值参数可以来自同一输出；函数不保存输入指针或复用旧字段。 */
    CHECK(vireo_pool_layout_compute(layout.element_size, layout.element_alignment,
                                    1, 16, &layout) == VIREO_OK);
    CHECK(layout.element_size == 13 && layout.element_alignment == 8);
    CHECK(layout.capacity == 1 && layout.slot_stride == 16 && layout.storage_bytes == 16);
    CHECK(vireo_pool_layout_compute(1, 1, 1, 1, &layout) == VIREO_OK);
    CHECK(layout.element_size == 1 && layout.element_alignment == 1);
    CHECK(layout.capacity == 1 && layout.slot_stride == 1 && layout.storage_bytes == 1);
    return 0;
}

static int test_small_domain(void) {
    static const size_t alignments[] = {1, 2, 4, 8, 16, 32};
    size_t cases = 0;
    for (size_t size = 1; size <= 64; ++size) {
        for (size_t a = 0; a < sizeof(alignments) / sizeof(alignments[0]); ++a) {
            size_t alignment = alignments[a];
            /* 安全小域内逐字节递增，不调用 checked 或复制其对齐算法。 */
            size_t stride = size;
            while (stride % alignment != 0) {
                ++stride;
            }
            for (size_t count = 1; count <= 8; ++count) {
                size_t bytes = 0;
                for (size_t slot = 0; slot < count; ++slot) {
                    bytes += stride;
                }
                CHECK(expect_layout(size, alignment, count, bytes, stride, bytes) == 0);
                CHECK(expect_layout(size, alignment, count, bytes + 1, stride, bytes) == 0);
                if (bytes > 1) {
                    CHECK(expect_failure(size, alignment, count, bytes - 1,
                                         VIREO_RESULT_RANGE) == 0);
                } else {
                    CHECK(expect_failure(size, alignment, count, 0,
                                         VIREO_RESULT_INVALID_ARGUMENT) == 0);
                }
                ++cases;
            }
        }
    }
    CHECK(cases == 3072);
    printf("pool layout small domain: %zu layouts, %zu budget checks\n", cases, cases * 3);
    return 0;
}

int main(void) {
    static int (*const groups[])(void) = {
        test_unaligned_size, test_already_aligned, test_minimum, test_c_type,
        test_invalid_arguments, test_budget, test_alignment_overflow,
        test_multiplication_overflow, test_maximum_values, test_repeated_output,
        test_small_domain
    };
    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); ++i) {
        if (groups[i]() != 0) {
            return EXIT_FAILURE;
        }
    }
    printf("test_pool_layout: %zu groups passed\n", sizeof(groups) / sizeof(groups[0]));
    return EXIT_SUCCESS;
}
