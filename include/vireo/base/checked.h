/*
 * PROJECT : VIREO
 * FILE    : checked.h
 * AUTHOR  : bitofux
 * DATE    : 2026-08-08
 * BRIEF   : 此模块负责：
 * -- 提供 size_t、uint32_t、uint64_t 的受检加法
 * -- 提供 size_t、uint32_t、uint64_t 的受检乘法
 * -- 提供 uint64_t 到 size_t 的受检窄化转换
 * -- 提供 size_t 的向上对齐和区间验证
 */

#ifndef VIREO_BASE_CHECKED_H
#define VIREO_BASE_CHECKED_H

#include <stddef.h>
#include <stdint.h>

#include <vireo/base/result.h>

/**
 * @brief 对两个 size_t 的参数值执行受检查加法
 *
 * 只有 left + right 的数学结果能够由 size_t 表示时才写入输出参数out
 *
 * @param[in] left 左操作数
 * @param[in] right 右操作数
 * @param[out] out 用于接收准确结果的非空指针；调用者保留所有权
 *
 * @retval VIREO_OK 加法成功，*out 已写入操作结果
 * @retval VIREO_RESULT_INVALID_ARGUMENT 无效的参数，这个函数中 out 为NULL时才返回
 * @retval VIREO_RESULT_OVERFLOW left + right 无法由 size_t 表示
 *
 * @note 如函数失败，则不会写入错误结果到out
 * @note 线程安全：thread-safe; 函数不访问或修改共享可变状态
 * @note errno：本函数不读取、不保存且不修改 errno
 */
vireo_result_t vireo_checked_size_add(size_t left, size_t right, size_t *out);

/**
 * @brief 对两个 size_t 的参数值执行受检查乘法
 *
 * 只有 left * right 的数学结果能够由 size_t 表示时才写入输出参数out
 *
 * @param[in] left 左操作数
 * @param[in] right 右操作数
 * @param[out] out 用于接收准确结果的非空指针；调用者保留所有权
 *
 * @retval VIREO_OK 乘法成功，*out 已写入操作结果
 * @retval VIREO_RESULT_INVALID_ARGUMENT 无效的参数，这个函数中 out 为NULL时才返回
 * @retval VIREO_RESULT_OVERFLOW left * right 无法由 size_t 表示
 *
 * @note 任意一个参数为0，则结果为0
 * @note 如函数失败，则不会写入错误结果到out
 * @note 线程安全：thread-safe; 函数不访问或修改共享可变状态
 * @note errno：本函数不读取、不保存且不修改 errno
 */
vireo_result_t vireo_checked_size_mul(size_t left, size_t right, size_t *out);

/**
 * @brief 对两个 uint32_t 的参数值执行受检查加法
 *
 * 只有 left + right 的数学结果能够由 uint32_t 表示时才写入输出参数out
 *
 * @param[in] left 左操作数
 * @param[in] right 右操作数
 * @param[out] out 用于接收准确结果的非空指针；调用者保留所有权
 *
 * @retval VIREO_OK 加法成功，*out 已写入操作结果
 * @retval VIREO_RESULT_INVALID_ARGUMENT 无效的参数，这个函数中 out 为NULL时才返回
 * @retval VIREO_RESULT_OVERFLOW left + right 无法由 uint32_t 表示
 *
 * @note 如函数失败，则不会写入错误结果到out
 * @note 线程安全：thread-safe; 函数不访问或修改共享可变状态
 * @note errno：本函数不读取、不保存且不修改 errno
 */
vireo_result_t vireo_checked_u32_add(uint32_t left, uint32_t right, uint32_t *out);

/**
 * @brief 对两个 uint32_t 值执行受检乘法
 *
 * 只有 left * right 的数学结果能够由 uint32_t 表示时才写入输出参数
 *
 * @param[in] left 左操作数
 * @param[in] right 右操作数
 * @param[out] out 用于接收准确结果的非空指针；调用者保留所有权
 *
 * @retval VIREO_OK 乘法成功，*out 已写入准确结果
 * @retval VIREO_RESULT_INVALID_ARGUMENT out 为 NULL
 * @retval VIREO_RESULT_OVERFLOW left * right 无法由 uint32_t 表示
 *
 * @note 任一操作数为 0 时结果为 0
 * @note 失败时不修改 *out
 * @note 线程安全：thread-safe；函数不访问或修改共享可变状态
 * @note errno：本函数不读取、不保存且不修改 errno
 */
vireo_result_t vireo_checked_u32_mul(uint32_t left, uint32_t right, uint32_t *out);

/**
 * @brief 对两个 uint64_t 值执行受检加法
 *
 * 只有 left + right 的数学结果能够由 uint64_t 表示时才写入输出参数
 *
 * @param[in] left 左操作数
 * @param[in] right 右操作数
 * @param[out] out 用于接收准确结果的非空指针；调用者保留所有权
 *
 * @retval VIREO_OK 加法成功，*out 已写入准确结果
 * @retval VIREO_RESULT_INVALID_ARGUMENT out 为 NULL
 * @retval VIREO_RESULT_OVERFLOW left + right 无法由 uint64_t 表示
 *
 * @note 失败时不修改 *out
 * @note 线程安全：thread-safe；函数不访问或修改共享可变状态
 * @note errno：本函数不读取、不保存且不修改 errno
 */
vireo_result_t vireo_checked_u64_add(uint64_t left, uint64_t right, uint64_t *out);

/**
 * @brief 对两个 uint64_t 值执行受检乘法
 *
 * 只有 left * right 的数学结果能够由 uint64_t 表示时才写入输出参数
 *
 * @param[in] left 左操作数
 * @param[in] right 右操作数
 * @param[out] out 用于接收准确结果的非空指针；调用者保留所有权
 *
 * @retval VIREO_OK 乘法成功，*out 已写入准确结果
 * @retval VIREO_RESULT_INVALID_ARGUMENT out 为 NULL
 * @retval VIREO_RESULT_OVERFLOW left * right 无法由 uint64_t 表示
 *
 * @note 任一操作数为 0 时结果为 0
 * @note 失败时不修改 *out
 * @note 线程安全：thread-safe；函数不访问或修改共享可变状态
 * @note errno：本函数不读取、不保存且不修改 errno
 */
vireo_result_t vireo_checked_u64_mul(uint64_t left, uint64_t right, uint64_t *out);

/**
 * @brief 将 uint64_t 值受检转换为 size_t
 *
 * 只有 value 能够由当前平台的 size_t 完整表示时才执行转换
 *
 * @param[in] value 要转换的 uint64_t 值
 * @param[out] out 用于接收转换结果的非空指针；调用者保留所有权
 *
 * @retval VIREO_OK 转换成功，将转换的结果写入out
 * @retval VIREO_RESULT_INVALID_ARGUMENT out 为 NULL
 * @retval VIREO_RESULT_RANGE value 无法由当前平台的 size_t 表示
 *
 * @note 本函数不执行截断转换，不可以被当前平台的 size_t 完整表示就视为失败
 * @note 失败不修改 *out
 * @note 线程安全：thread-safe；函数不访问或修改共享可变状态
 * @note errno：本函数不读取、不保存且不修改 errno
 */
vireo_result_t vireo_checked_u64_to_size(uint64_t value, size_t *out);

/**
 * @brief 将 size_t 值向上对齐到指定正整数的倍数
 *
 * alignment 可以是任意正整数
 *
 * @param[in] value 要对齐的值
 * @param[in] alignment 要对齐的单位；必须大于0
 * @param[out] out 用于接收对齐结果的非空指针；调用者保留所有权
 *
 * @retval VIREO_OK 对齐成功，*out 写入对齐结果
 * @retval VIREO_RESULT_INVALID_ARGUMENT out 为 NULL 或者 alignment 为 0
 * @retval VIREO_RESULT_OVERFLOW 对齐结果无法由 size_t 表示
 *
 * @note value 已经对齐时原值直接写入 *out
 * @note 失败时不修改 *out
 * @note 线程安全：thread-safe；函数不访问或修改共享可变状态
 * @note errno：本函数不读取、不保存且不修改 errno
 */
vireo_result_t vireo_checked_size_align_up(size_t value, size_t alignment, size_t *out);

/**
 * @brief 验证半开区间 [offset,offset+length) 是否位于 [0,limit) 内
 *
 * 此函数不直接计算 offset + length，因此不会因为区间检查本身发生整数回绕
 * length 为 0 且 offset 等于 limit 时，空区间被视为有效
 *
 * @param[in] offset 区间起始偏移
 * @param[in] length 区间长度
 * @param[in] limit 可用范围的上界
 *
 * @retval VIREO_OK 整个区间位于限制内
 * @retval VIREO_RESULT_RANGE offset 大于 limit，或length 超出剩余范围
 *
 * @note 本函数没有输出参数和所有权转移
 * @note 线程安全：thread-safe；函数不访问或修改共享可变状态
 * @note errno：本函数不读取、不保存且不修改errno
 */
vireo_result_t vireo_checked_size_range(size_t offset, size_t length, size_t limit);
#endif /* VIREO_BASE_CHECKED_H */
