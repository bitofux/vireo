/*
 * PROJECT : VIREO
 * FILE    : pool.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-02
 * BRIEF   : 此模块负责：
 * -- 计算固定大小对象槽位的受检步长与存储字节需求
 * -- 在调用者明确的槽位预算内提交按值布局
 * -- 在总申请预算内创建、观测和销毁固定容量池
 */

#ifndef VIREO_BASE_POOL_H
#define VIREO_BASE_POOL_H

#include <stddef.h>
#include <stdint.h>

#include <vireo/base/result.h>

/**
 * @brief 固定大小均匀槽位的数值布局，不拥有对象或存储
 * @note 可按值复制；不冻结 sizeof、padding 或序列化 ABI。
 */
typedef struct vireo_pool_layout {
    size_t element_size;      /**< 每个对象的有效字节数，正值。 */
    size_t element_alignment; /**< 槽位间距的对齐单位，正二次幂，单位为字节。 */
    size_t capacity;          /**< 槽位数量，正值，不是字节容量或当前在用数。 */
    size_t slot_stride;       /**< 不小于 element_size 的最小 element_alignment 倍数。 */
    size_t storage_bytes;     /**< slot_stride * capacity，含每槽完整尾部填充。 */
} vireo_pool_layout_t;

/**
 * @brief 受检计算槽位布局并验证调用者提供的槽位存储预算
 *
 * 按参数合法性、对齐可表示性、乘法可表示性、预算上界的顺序检查。
 * 成功只证明数值布局，不分配存储或创建可 acquire 的对象池。
 *
 * @param[in] element_size 每个对象的正字节数，按值传入，通常来自 sizeof(T)。
 * @param[in] element_alignment 正二次幂字节单位，通常来自 _Alignof(T)。
 * @param[in] capacity 正槽位数量，按值传入。
 * @param[in] max_storage_bytes 正槽位存储字节预算，等于需求时允许成功。
 * @param[out] out 非 NULL、存活、正确对齐且可写的布局；调用者保留所有权。
 * @retval VIREO_OK 完整提交五个布局字段，storage_bytes 不超过预算。
 * @retval VIREO_RESULT_INVALID_ARGUMENT out 为 NULL、任一数值输入为零，
 *     或 element_alignment 不是二次幂。
 * @retval VIREO_RESULT_OVERFLOW 对齐步长或步长乘槽位数量无法由 size_t 表示。
 * @retval VIREO_RESULT_RANGE 可表示的 storage_bytes 超过 max_storage_bytes。
 * @note 输出保持：任何失败都不修改 out 的任何字节；成功前不发布中间值。
 * @note 所有权与生命周期：仅在调用期间借用 out，不保存指针，无资源转移。
 * @note 线程安全：thread-safe；独立输出可并发，共享输出的读写由调用者同步。
 * @note errno：不读取、不保存且不修改 errno；没有动态分配或 I/O。
 * @note 对齐边界：只验证数值二次幂，不保证实际分配器支持该对齐，也不验证
 *     首地址对齐；成功不授予任何对象指针或解引用权限。
 * @note 预算边界：只计槽位存储，不含未来池头、管理元数据、分配器开销、
 *     页粒度、RSS、对象间接拥有的资源或全局内存预算；不保证实际分配成功。
 */
vireo_result_t vireo_pool_layout_compute(size_t element_size,
                                         size_t element_alignment,
                                         size_t capacity,
                                         size_t max_storage_bytes,
                                         vireo_pool_layout_t *out);

/** 每池总申请字节硬上限，64 MiB；含控制块、槽位区和管理元数据，不等于 RSS 或全局预算。 */
#define VIREO_POOL_MAX_MEMORY ((size_t)67108864)

/** 唯一拥有型池；私有布局/sizeof 不公开，同池访问须外部同步。 */
typedef struct vireo_pool vireo_pool_t;

/** 创建时按值读取的选项，无默认值；不持有对象类型或间接资源。 */
typedef struct vireo_pool_options {
    size_t element_size;      /**< 每个对象的正字节数，通常来自 sizeof(T)。 */
    size_t element_alignment; /**< 正二次幂，实际支持至 _Alignof(max_align_t)。 */
    size_t capacity;          /**< 固定正槽位数，创建后不增长或搬迁。 */
    size_t max_memory_bytes;  /**< 总申请预算，1..VIREO_POOL_MAX_MEMORY。 */
} vireo_pool_options_t;

/** 按值观测，不拥有池或槽位；销毁池不影响已经取得的数值副本。 */
typedef struct vireo_pool_info {
    vireo_pool_layout_t layout; /**< 创建时验证的槽位布局，保持不变。 */
    size_t allocation_bytes;   /**< 控制块、完整槽位区与元数据申请字节之和。 */
    size_t max_memory_bytes;   /**< 创建时调用者明确给出的总申请预算。 */
    size_t metadata_bytes;     /**< 独立槽位元数据区的申请字节数，非公开布局。 */
    uint64_t pool_id;          /**< 本库进程范围非零且不复用的池身份，非持久标识。 */
    uint64_t last_generation;  /**< 已成功发放的最后序号，零表示从未发放。 */
    size_t in_use_count;       /**< 当前有未归还租约的槽位数。 */
    size_t available_count;    /**< capacity - in_use_count；序号耗尽仍不发放。 */
} vireo_pool_info_t;

/** 数值租约，不拥有池或间接资源，不含对象指针；全零为无租约。 */
typedef struct vireo_pool_lease {
    uint64_t pool_id;     /**< 非零池身份；只可用于仍存活的目标池。 */
    size_t slot_index;   /**< 小于 capacity 的槽号，不是字节偏移。 */
    uint64_t generation; /**< 池内唯一非零发放序号；不回绕。 */
} vireo_pool_lease_t;

/**
 * @brief 在显式总预算内创建固定容量池，全部成功后发布唯一所有权
 * @param[in] options 非 NULL、存活且可读的选项，仅在调用期间借用。
 * @param[in,out] out_pool 非 NULL、正确对齐且可写的拥有者地址，入口
 *     *out_pool 必须为 NULL；成功取得对象，最终以 destroy 消费该句柄。
 * @retval VIREO_OK 控制块、连续槽位区与槽外元数据均已取得，发布完整空池。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 参数为 NULL、入口句柄非 NULL、
 *     任一选项为零或 element_alignment 不是二次幂。
 * @retval VIREO_RESULT_OVERFLOW 槽位/元数据乘法或总量加法不可表示，或本库进程池身份耗尽。
 * @retval VIREO_RESULT_RANGE 对齐超过 _Alignof(max_align_t)、预算超过硬限，
 *     或可表示的总需求超过预算；需求等于预算允许成功。
 * @retval VIREO_RESULT_NO_MEMORY 任一分配失败，已获资源逆序释放。
 * @note 顺序：参数合法性→槽位布局/总量可表示性→实际对齐/预算→身份→分配。
 *     算术不可表示优先于 RANGE；身份耗尽拒绝时不分配。
 * @note 失败保持 *out_pool；不清零槽位区、不初始化用户对象、不授予对象指针。
 * @note 所有权：池独占控制块、槽位区和元数据；选项和输出存储互不重叠，不能
 *     位于被创建资源内。复制句柄不复制所有权，不管理对象间接资源。
 * @note 总预算含模块请求的控制块、完整槽位区和元数据；不含分配器开销、页/RSS、
 *     对象间接资源或全局多池预算，不保证申请成功或实时延迟。
 * @note 池身份由原子计数器分配，零保留且不复用；分配失败可消耗身份，
 *     身份耗尽不再创建。标识只在本库单实例进程内有效，非跨进程/持久标识。
 * @note 线程安全：独立池的独立创建可并发；同池externally-synchronized；
 *     拥有者地址须独占，身份原子不构成对象同步，无lock-free/实时保证。
 * @note errno：所有路径保持调用前值，失败依据结果码判断。
 */
vireo_result_t vireo_pool_create(vireo_pool_options_t const *options,
                                 vireo_pool_t **out_pool);

/**
 * @brief 按值读取固定布局、总申请字节与创建预算
 * @param[in] pool 非 NULL、存活对象，仅在调用期间借用。
 * @param[out] out_info 非 NULL、正确对齐且可写的独立输出，不与池存储重叠。
 * @retval VIREO_OK 提交完整数值副本，不改变池或授予槽位访问权。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 任一参数为 NULL，整个输出保持。
 * @note 所有权：调用者保留输出；副本不含资源指针，不延长池的生命期。
 * @note 线程安全：externally-synchronized；观测也须与同池销毁协调。
 * @note errno：不读取、不保存且不修改 errno；不分配、不执行 I/O。
 */
vireo_result_t vireo_pool_inspect(vireo_pool_t const *pool, vireo_pool_info_t *out_info);

/**
 * @brief 从固定空闲槽取得数值租约和对象借用，不分配或搬移
 * @param[in,out] pool 非 NULL、存活且由调用者外部同步的池，保留所有权。
 * @param[out] out_lease 非 NULL、存活、正确对齐且可写的独立租约输出。
 * @param[out] out_object 非 NULL、存活、正确对齐且可写的独立指针输出。
 * @retval VIREO_OK 同时提交租约与对象首地址，in_use_count 增一。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 任一参数为 NULL。
 * @retval VIREO_RESULT_OVERFLOW 池发放序号耗尽，优先于满池；不回绕或复用。
 * @retval VIREO_RESULT_BUSY 没有空闲槽。
 * @note 失败不修改两个输出的任何字节或池；输出互不重叠且不在池自有资源内。
 *     成功覆盖输出，调用者不得因此丢失尚未归还的唯一租约记录。
 * @note 借用：地址支持 element_alignment，仅 element_size 字节可用于对象；
 *     调用者初始化对象，不保证原值/清零，不准访问槽位填充或相邻对象。
 *     在匹配租约成功 release 时借用结束，之后不得读写旧指针；其他租约
 *     的 acquire/release 与失败操作不结束此借用。间接资源由调用者先清理。
 * @note 租约可按值复制但没有新增权限，归还任一副本使全部副本失效；
 *     数值租约不会延长池生命期，不支持裸指针归还或认证/抗恶意伪造。
 * @note 线程安全：externally-synchronized，身份原子不保障同池访问或对象发布。
 * @note errno：不读取、不保存且不修改 errno，无分配或 I/O。
 */
vireo_result_t vireo_pool_acquire(vireo_pool_t *pool, vireo_pool_lease_t *out_lease,
                                  void **out_object);

/**
 * @brief 校验数值租约，归还槽位并清空传入租约的三个字段
 * @param[in,out] pool 非 NULL、存活且外部同步的目标池，保留所有权。
 * @param[in,out] lease 非 NULL、存活、正确对齐且可写，存储不在池自有资源内。
 * @retval VIREO_OK 归还一次并将租约字段置零，匹配对象借用结束。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 参数为 NULL、非空租约有零身份/代际，
 *     或 pool_id 不属于目标池。
 * @retval VIREO_RESULT_RANGE 相同身份下 slot_index >= capacity。
 * @retval VIREO_RESULT_NOT_FOUND 全零租约、槽位已空闲或 generation 不匹配。
 * @note 顺序：指针参数→全零→非零身份/代际→池身份→槽号→在用/代际。
 *     在访问元数据前校验数值，不检查或读取调用者的旧对象指针。
 * @note 失败保持租约全部字节/池状态/现有借用；成功不承诺租约padding清零。
 *     不初始化/擦除对象字节，不关闭fd、不销毁buffer或调用析构回调。
 * @note 线程安全：externally-synchronized；先结束对象使用并清理间接资源再归还。
 * @note errno：不读取、不保存且不修改 errno，无分配或 I/O。
 */
vireo_result_t vireo_pool_release(vireo_pool_t *pool, vireo_pool_lease_t *lease);

/**
 * @brief 逆序释放空池自有内存，消费并清空唯一拥有者句柄
 * @param[in,out] pool 非 NULL、正确对齐且可写的拥有者地址；*pool 可为 NULL，
 *     非空时须为 create 取得且尚未销毁的唯一对象，句柄存储不在自有资源内。
 * @retval VIREO_OK 已释放并置 NULL，或入口为空句柄的成功空操作。
 * @retval VIREO_RESULT_INVALID_ARGUMENT pool 地址为 NULL。
 * @retval VIREO_RESULT_BUSY 存在未归还租约，保持owner/全部资源/状态与借用。
 * @note 所有旧句柄别名失效，不清理用户对象间接资源或提供安全擦除。
 * @note 线程安全：externally-synchronized；须先停止同池全部操作。
 * @note errno：所有路径保持调用前值，不依赖 free 的 errno 行为。
 */
vireo_result_t vireo_pool_destroy(vireo_pool_t **pool);

#endif /* VIREO_BASE_POOL_H */
