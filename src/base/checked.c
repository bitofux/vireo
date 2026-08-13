/*
 * PROJECT : VIREO
 * FILE    : checked.c
 * AUTHOR  : bitofux
 * DATE    : 2026-08-08
 * BRIEF   : vireo_checked 模块的实现
 * -- 在执行加法和乘法前证明结果能够由目标类型表示
 * -- 在窄化转换前证明输入能够由目标类型完整表示
 * -- 在不产生整数回绕的前提下完成对齐和区间检查
 */

#include <vireo/base/checked.h>

/* 执行两个 size_t 类型参数的受检加法运算 */
vireo_result_t vireo_checked_size_add(size_t left, size_t right, size_t *out) {
    // 若 out 为 NULL，则表示无效参数
    if (out == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    // 若 right > SIZE_MAX - left，则表示会有溢出
    if (right > SIZE_MAX - left) {
        return VIREO_RESULT_OVERFLOW;
    }

    // 将正确的加法结果写入到 *out
    *out = left + right;

    return VIREO_OK;
}

/* 执行两个 size_t 类型参数的受检乘法运算 */
vireo_result_t vireo_checked_size_mul(size_t left, size_t right, size_t *out) {
    // 若 out 为 NULL，则表示无效参数
    if (out == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    // 若 left 的值不为 0 且 right > SIZE_MAX / left
    if ((left != 0) && right > SIZE_MAX / left) {
        return VIREO_RESULT_OVERFLOW;
    }

    // 将正确的乘法结果写入 *out
    *out = left * right;

    return VIREO_OK;
}

/* 执行两个 uint32_t 类型参数的受检加法运算 */
vireo_result_t vireo_checked_u32_add(uint32_t left, uint32_t right, uint32_t *out) {
    // 若 out 的值为 NULL，则表示无效参数
    if (out == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    // 若 right > UINT32_MAX - left，则表示会有溢出
    if (right > UINT32_MAX - left) {
        return VIREO_RESULT_OVERFLOW;
    }

    // 将正确的加法结果写入
    *out = left + right;

    return VIREO_OK;
}

/* 执行两个 uint32_t 类型参数的受检乘法运算 */
vireo_result_t vireo_checked_u32_mul(uint32_t left, uint32_t right, uint32_t *out) {
    // 若 out 的值为 NULL，则表示无效参数
    if (out == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    // 若 left 的值不为 0 且 right > UINT32_MAX / left
    if ((left != 0) && right > UINT32_MAX / left) {
        return VIREO_RESULT_OVERFLOW;
    }

    // 将正确的乘法结果写入
    *out = left * right;

    return VIREO_OK;
}

/* 执行两个 uint64_t 类型参数的受检加法运算 */
vireo_result_t vireo_checked_u64_add(uint64_t left, uint64_t right, uint64_t *out) {
    // 若 out 的值为 NULL，则表示无效参数
    if (out == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    // 若 right > UINT64_MAX - left，则表示发生整数溢出
    if (right > UINT64_MAX - left) {
        return VIREO_RESULT_OVERFLOW;
    }

    // 将正确的加法结果写入 *out
    *out = left + right;

    return VIREO_OK;
}

/* 执行两个 uint64_t 类型参数的受检乘法运算 */
vireo_result_t vireo_checked_u64_mul(uint64_t left, uint64_t right, uint64_t *out) {
    // 若 out 的值为 NULL，则表示参数无效
    if (out == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    // left 非 0 且 right 大于可安全相乘的最大值时，乘法将溢出
    if ((left != 0) && right > UINT64_MAX / left) {
        return VIREO_RESULT_OVERFLOW;
    }

    // 将正确的乘法结果写入 *out
    *out = left * right;

    return VIREO_OK;
}

/* 执行 uint64_t 的窄化转换 */
vireo_result_t vireo_checked_u64_to_size(uint64_t value, size_t *out) {
    // 若 out 为 NULL，则表示参数无效
    if (out == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

#if SIZE_MAX < UINT64_MAX
    // 若当前平台的 size_t 较窄时，value 必须位于[0,SIZE_MAX]
    if (value > (uint64_t)SIZE_MAX) {
        return VIREO_RESULT_RANGE;
    }
#endif
    // 将转换后的结果写入 *out
    *out = (size_t)value;

    return VIREO_OK;
}

/* 执行 value 的向上对齐 */
vireo_result_t vireo_checked_size_align_up(size_t value, size_t alignment, size_t *out) {
    // 若 out 的值为 NULL，alignment 的值为 0
    if (out == NULL || alignment == 0) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    // 若 value 已经是 alignment 的倍数，则返回成功
    size_t remainder = value % alignment;

    if (remainder == 0) {
        *out = value;
        return VIREO_OK;
    }

    // value 还差 increment 达到 alignment 倍数的最小正整数
    size_t increment = alignment - remainder;

    /*
     * 复用受检加法完成最终对齐计算
     * 若加法失败，直接把相同错误返回给调用者即可
     */
    return vireo_checked_size_add(value, increment, out);
}

/* 执行区间有效范围的检查 */
vireo_result_t vireo_checked_size_range(size_t offset, size_t length, size_t limit) {
    // 若 offset 大于 limit，则表示范围无效
    if (offset > limit) {
        return VIREO_RESULT_RANGE;
    }

    // 若 length > limit - offset，则表示范围无效
    if (length > limit - offset) {
        return VIREO_RESULT_RANGE;
    }

    return VIREO_OK;
}
