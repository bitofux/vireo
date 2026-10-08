/*
 * PROJECT : VIREO
 * FILE    : handle.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-08
 * BRIEF   : 此模块负责：
 * -- 定义 timer 的数值身份与空句柄
 * -- 查询句柄形态和逐字段相等关系
 * -- 受检计算下一代序号，不执行实际发放
 */

#ifndef VIREO_TIMER_HANDLE_H
#define VIREO_TIMER_HANDLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <vireo/base/result.h>

/**
 * @brief 不拥有资源的 timer 数值身份
 *
 * 全零为无句柄；正常非空句柄的 owner_id 和 generation 均非零。
 * 其他零值组合为畸形；slot_index 为 0 可以表示正常槽号。
 * 三字段都没有时间单位，不是 deadline、wire 短 handle 或安全凭据。
 * 不冻结 sizeof、padding 或序列化 ABI；相等关系只比较三个逻辑字段。
 */
typedef struct vireo_timer_handle {
    uint64_t owner_id;   /**< 所属管理实例的数值身份；数值构造入口不分配身份。 */
    size_t slot_index;   /**< 槽号，不是字节偏移；本模块不判断实际容量。 */
    uint64_t generation; /**< 使用代次，不是 tick；正常非空时为 1..UINT64_MAX。 */
} vireo_timer_handle_t;

/**
 * @brief 用显式三字段构造正常非空的数值句柄
 *
 * 只验证形态，不登记 timer 或认证 owner、容量、活跃性及操作权限。
 * 空句柄由调用者以全零初始化取得，不通过本函数构造。
 *
 * @param[in] owner_id
 *     非零管理实例数值身份；UINT64_MAX 也是可表达的非零值。
 * @param[in] slot_index
 *     按值槽号，0..SIZE_MAX 均可表达；有效槽范围由后续 owner 检查。
 * @param[in] generation
 *     非零使用代次，1..UINT64_MAX；本函数不检查是否已经发放。
 * @param[out] out_handle
 *     非空、存活、正确对齐且可写的句柄地址；调用者保留所有权。
 *
 * @retval VIREO_OK
 *     完整写入三个输入字段，得到正常非空形态。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     out_handle 为 NULL、owner_id 为 0 或 generation 为 0。
 *
 * @note
 *     输出保持：任何失败保持整个输出对象的字节；成功不承诺 padding 内容。
 * @note
 *     借用与别名：地址只借到返回，不保存；按值输入可来自输出的原字段存储。
 * @note
 *     地址约束：输出不得指向 errno 存储；调用者保证有效、对齐且可写。
 * @note
 *     线程安全：thread-safe；共享输出由调用者同步，无内部可变状态。
 * @note
 *     errno：不读取、不保存且不修改 errno，无分配、I/O 或时钟采样。
 * @note
 *     身份边界：三元组不复用及当前活跃校验由后续 owner 负责；构造不是取得资源。
 */
vireo_result_t vireo_timer_handle_make(uint64_t owner_id, size_t slot_index,
                                       uint64_t generation, vireo_timer_handle_t *out_handle);

/**
 * @brief 判断形态合法的数值句柄是否全零为空
 *
 * 只区分全零空句柄和正常非空形态；不查询 timer 的登记或生命期。
 *
 * @param[in] handle
 *     按值传入的已初始化句柄；可为空或正常非空。
 * @param[out] out_empty
 *     非空、存活、正确对齐且可写的 bool 地址；调用者持有。
 *
 * @retval VIREO_OK
 *     全零句柄输出 true，正常非空形态输出 false。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     out_empty 为 NULL 或 handle 为畸形零值组合。
 *
 * @note
 *     输出与借用：失败保持输出，地址只借到返回，不保存，不得指向 errno 存储。
 * @note
 *     线程安全：thread-safe；共享输出由调用者同步。
 * @note
 *     errno：不读取、不保存且不修改 errno；无资源或系统采样。
 * @note
 *     有效性边界：历史、伪造或已失效的数值也可具有非空形态，false 不授予操作权。
 */
vireo_result_t vireo_timer_handle_is_empty(vireo_timer_handle_t handle, bool *out_empty);

/**
 * @brief 对两个形态合法的句柄逐逻辑字段查询数值相等
 *
 * owner_id、slot_index 和 generation 三者均相同才相等；不比较 padding。
 * 两个空句柄也相等，这仅是数值关系，不代表它们对应一个 timer。
 *
 * @param[in] left
 *     按值传入的已初始化句柄；可为空或正常非空。
 * @param[in] right
 *     按值传入的已初始化句柄；可为空或正常非空。
 * @param[out] out_equal
 *     非空、存活、正确对齐且可写的 bool 地址；调用者持有。
 *
 * @retval VIREO_OK
 *     输出三个逻辑字段的相等关系。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     out_equal 为 NULL，或任一个输入句柄为畸形零值组合。
 *
 * @note
 *     输出与借用：失败保持输出，地址只借到返回，不保存，不得指向 errno 存储。
 * @note
 *     线程安全：thread-safe；共享输出由调用者同步，无内部可变状态。
 * @note
 *     errno：不读取、不保存且不修改 errno；不返回 NOT_FOUND 或查询 owner 状态。
 * @note
 *     生命周期边界：数值复制或相等不延长 owner/timer 生命期，不验证容量或活跃性。
 */
vireo_result_t vireo_timer_handle_equal(vireo_timer_handle_t left, vireo_timer_handle_t right,
                                        bool *out_equal);

/**
 * @brief 受检计算下一代的非零数值，不执行发放或更新计数器
 *
 * last_generation 为 0 时得到首代 1；UINT64_MAX - 1 得到 UINT64_MAX。
 * UINT64_MAX 后没有可表示的下一代，不回绕、重置或饱和。
 *
 * @param[in] last_generation
 *     按值输入的上一序号，0..UINT64_MAX 均可传；0 表示计算首代。
 * @param[out] out_generation
 *     非空、存活、正确对齐且可写的 uint64_t 地址；调用者持有。
 *
 * @retval VIREO_OK
 *     完整输出准确的 last_generation + 1，范围 1..UINT64_MAX。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     out_generation 为 NULL；参数拒绝优先于溢出检查。
 * @retval VIREO_RESULT_OVERFLOW
 *     last_generation 为 UINT64_MAX，下一代不可表示。
 *
 * @note
 *     输出与借用：失败保持输出，地址只借到返回，可写回输入原存储，不保存地址。
 * @note
 *     地址约束：输出不得指向 errno 存储；调用者保证有效、对齐且可写。
 * @note
 *     线程安全：thread-safe；不是原子发放，同一 counter 的读改写须由 owner 同步。
 * @note
 *     errno：不读取、不保存且不修改 errno；无系统调用或资源分配。
 * @note
 *     耗尽边界：不决定整个 owner 停止发放或单槽退休，后续管理模块明确处理。
 */
vireo_result_t vireo_timer_handle_next_generation(uint64_t last_generation,
                                                  uint64_t *out_generation);

#endif /* VIREO_TIMER_HANDLE_H */
