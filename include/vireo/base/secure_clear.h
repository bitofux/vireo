/*
 * PROJECT : VIREO
 * FILE    : secure_clear.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 存活自有字节区的显式擦除合同
 */
#ifndef VIREO_BASE_SECURE_CLEAR_H
#define VIREO_BASE_SECURE_CLEAR_H

#include <vireo/base/result.h>

#include <stddef.h>

/**
 * @brief 用不可省略的逐字节写零擦除指定存活区间，不释放内存
 *
 * @param[in,out] data
 *     借用的可写字节区；非零 size 时必须非 NULL，零长度允许 NULL。
 *     caller 保证整个区间存活、可写并独占访问，且不覆盖 errno 的存储。
 * @param[in] size
 *     精确擦除字节数，允许零；不得超过 data 实际可写区间，不根据字符串求长。
 *
 * @retval VIREO_OK
 *     指定区间全部写零；零长度不访问 data，重复擦除同样成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     非零 size 配 NULL data，不写任何字节。
 *
 * @note 所有权：不保存地址、不分配或释放；只擦此区间，其他副本仍由其 owner 清理。
 * @note 线程安全：不同且不重叠的存储可并行；同一区间的读写与生命周期由 caller 同步。
 *     volatile 字节写只用于保留擦除操作，不提供原子性或跨线程发布。
 * @note errno：不读取、不保存、不修改 errno，所有路径保持入口值。
 * @note 成本与范围：O(size)，无系统调用或线程取消点，不承诺硬实时或恒时；
 *     不保证寄存器、系统/第三方副本、swap、core 或崩溃后的内容清除。
 */
vireo_result_t vireo_secure_clear(void *data, size_t size);

#endif /* VIREO_BASE_SECURE_CLEAR_H */
