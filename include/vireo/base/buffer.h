/*
 * PROJECT : VIREO
 * FILE    : buffer.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-01
 * BRIEF   : 此模块负责：
 * -- 有界连续字节存储的唯一所有权与生命周期
 * -- 完整追加、只读借用、前缀消费与显式整理/预留/回缩
 */
#ifndef VIREO_BASE_BUFFER_H
#define VIREO_BASE_BUFFER_H

#include <stddef.h>
#include <stdint.h>
#include <vireo/base/result.h>

/** 每对象当前存储硬上限，64 MiB；换区可暂存新旧两区，不含对象/分配器开销或全局预算。 */
#define VIREO_BUFFER_MAX_CAPACITY ((size_t)67108864)

/** 唯一拥有型对象；布局、sizeof、padding 不公开，不可复制或序列化。 */
typedef struct vireo_buffer vireo_buffer_t;

/** 按值观测，不含资源所有权；不能作为未来状态或可写指针的授权。 */
typedef struct vireo_buffer_info {
    size_t capacity;      /**< 当前分配容量，可显式 reserve 增长或 shrink 回缩。 */
    size_t readable_size; /**< 已初始化且尚未消费的字节数。 */
    size_t tail_space;    /**< 尾部连续可追加字节数，不含已消费的头部空洞。 */
} vireo_buffer_info_t;

/**
 * @brief 创建指定初始容量的空 buffer，全部成功后发布唯一所有权
 * @param[in] capacity 初始字节容量，1..VIREO_BUFFER_MAX_CAPACITY，无默认值。
 * @param[in,out] out_buffer 非空拥有者句柄，入口 *out_buffer 必须为 NULL；
 *     成功接管对象，调用者最终用 vireo_buffer_destroy 释放。
 * @retval VIREO_OK 成功发布空对象，capacity 已分配。
 * @retval VIREO_RESULT_INVALID_ARGUMENT out_buffer 为 NULL 或入口值非 NULL。
 * @retval VIREO_RESULT_RANGE capacity 为 0 或超过硬上限。
 * @retval VIREO_RESULT_NO_MEMORY 对象或字节区分配失败。
 * @note 失败保持 *out_buffer 并释放已取得内存；不隐式降级容量。
 * @note 线程安全：externally-synchronized；输出句柄须独占。
 * @note errno：所有路径保持调用前 errno，分配失败依据返回值判断。
 * @note 仅初始化逻辑空态，不清零全部容量，不生成字符串终止符。
 */
vireo_result_t vireo_buffer_create(size_t capacity, vireo_buffer_t **out_buffer);

/**
 * @brief 释放全部自有内存并消费拥有者句柄
 * @param[in,out] buffer 非空拥有者句柄；*buffer 可为 NULL，非空时必须是
 *     create 取得且未被其他句柄消费的唯一对象，由本调用释放并置 NULL。
 * @retval VIREO_OK 已销毁并置 NULL，或入口已为 NULL 的成功空操作。
 * @retval VIREO_RESULT_INVALID_ARGUMENT buffer 为 NULL。
 * @note 线程安全：externally-synchronized；须先停止全部操作和借用读取。
 * @note 所有旧别名与 view 立即失效；句柄存储不得位于被释放对象内。
 * @note errno：所有路径保持调用前 errno；不提供安全擦除承诺。
 */
vireo_result_t vireo_buffer_destroy(vireo_buffer_t **buffer);

/**
 * @brief 按值读取当前容量、可读长度和尾部空间
 * @param[in] buffer 非空存活对象，仅在调用期间借用。
 * @param[out] out_info 非空输出，调用者持有且独占，不与 buffer 存储重叠。
 * @retval VIREO_OK 提交完整观测；不改变 buffer 或既有 view。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 任一参数为 NULL。
 * @note 失败保持 out_info；线程安全：externally-synchronized，同对象访问须协调。
 * @note errno：不读取、不保存且不修改 errno；观测不承诺状态以后保持。
 */
vireo_result_t vireo_buffer_inspect(vireo_buffer_t const *buffer,
                                    vireo_buffer_info_t *out_info);

/**
 * @brief 将借用输入完整复制到尾部，不分配、不自动整理
 * @param[in,out] buffer 非空存活对象，调用者持有，操作期间独占。
 * @param[in] data 调用期间借用的字节，size 非零时必须非 NULL；长度通过
 *     算术/容量检查时须真实可读至少 size 字节，且区域不得与对象或其
 *     整个字节分配重叠。超限/溢出长度在读取输入字节之前拒绝。
 * @param[in] size 字节数；0 时 data 可为 NULL，不读取 data。
 * @retval VIREO_OK 完整复制并推进写索引，0 长度为成功空操作。
 * @retval VIREO_RESULT_INVALID_ARGUMENT buffer 为 NULL 或非零 size 配 NULL data。
 * @retval VIREO_RESULT_OVERFLOW 写索引加 size 无法由 size_t 表示。
 * @retval VIREO_RESULT_RANGE 可表示的新末端超过当前容量。
 * @note 所有失败保持全部自有字节、索引与既有 view；不截断或部分追加。
 * @note 成功（含零长度）结束全部既有 view 借用，继续读取前必须重新 peek。
 * @note 部分 consume 留下的头部空间不自动复用；全部 consume 后可复用全容量。
 * @note 线程安全：externally-synchronized；输入不能并发修改。
 * @note errno：不读取、不保存且不修改 errno；不执行 I/O 或日志。
 */
vireo_result_t vireo_buffer_append(vireo_buffer_t *buffer, uint8_t const *data, size_t size);

/**
 * @brief 借用完整的未消费连续字节区域，空态返回 NULL/0
 * @param[in] buffer 非空存活对象，调用期间借用。
 * @param[out] out_data 非空指针输出；成功得到 buffer 所有的只读借用，
 *     不得修改或释放，空态为 NULL。
 * @param[out] out_size 非空字节长度输出，空态为 0；调用者保留输出存储所有权。
 * @retval VIREO_OK 同时提交指针与长度，不改变 buffer 或其他 view。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 任一参数为 NULL，两个输出均保持。
 * @note 两个输出存储互不重叠，也不与对象及其字节存储重叠。
 * @note view 有效到下一次成功 append/consume/compact/reserve/shrink（含空操作）或 destroy；
 *     失败操作和 inspect/peek 不使其失效。复制指针不复制数据或延长生命期。
 * @note 线程安全：externally-synchronized；借用读取期间不得修改/销毁对象。
 * @note errno：不读取、不保存且不修改 errno；不验证协议或 NUL 终止。
 */
vireo_result_t vireo_buffer_peek(vireo_buffer_t const *buffer,
                                 uint8_t const **out_data, size_t *out_size);

/**
 * @brief 消费已处理前缀，全部消费后将读写索引归零
 * @param[in,out] buffer 非空存活对象，调用期间独占，所有权不转移。
 * @param[in] size 消费字节数，0..当前 readable_size。
 * @retval VIREO_OK 推进读索引，或全空时归零；size=0 为成功空操作。
 * @retval VIREO_RESULT_INVALID_ARGUMENT buffer 为 NULL。
 * @retval VIREO_RESULT_RANGE size 超过当前可读长度。
 * @note 失败保持全部状态与 view；成功（含零长度）结束全部既有 view 借用。
 * @note 不搬移、清零、缩小或释放字节存储；容量保持，旧字节不得据此读取。
 * @note 线程安全：externally-synchronized；errno：不读取、不保存且不修改。
 */
vireo_result_t vireo_buffer_consume(vireo_buffer_t *buffer, size_t size);

/**
 * @brief 将未消费字节整理到存储起点，回收头部空洞为尾部空间
 * @param[in,out] buffer 非空存活对象，调用期间独占，所有权不转移。
 * @retval VIREO_OK 未读顺序/长度和容量保持，读索引为 0，写索引为可读长度。
 * @retval VIREO_RESULT_INVALID_ARGUMENT buffer 为 NULL。
 * @note 不分配、不缩小容量；仅搬移未读字节，不提供旧字节安全擦除。
 * @note 成功（含无需搬移的空操作）结束全部既有 view，须重新 peek。
 * @note 失败保持全部状态与 view；线程安全：externally-synchronized。
 * @note errno：不读取、不保存且不修改；不执行 I/O 或日志。
 */
vireo_result_t vireo_buffer_compact(vireo_buffer_t *buffer);

/**
 * @brief 保证最低尾部空闲字节数，必要时整理或扩容，保留全部未读字节
 * @param[in,out] buffer 非空存活对象，调用期间独占，所有权不转移。
 * @param[in] min_tail_space 最低可追加字节数，允许 0；不是目标总容量。
 * @retval VIREO_OK tail_space 至少为请求值，未读字节顺序/长度保持，不追加数据。
 * @retval VIREO_RESULT_INVALID_ARGUMENT buffer 为 NULL。
 * @retval VIREO_RESULT_OVERFLOW readable_size 加请求无法由 size_t 表示。
 * @retval VIREO_RESULT_RANGE 可表示的最低所需容量超过 VIREO_BUFFER_MAX_CAPACITY。
 * @retval VIREO_RESULT_NO_MEMORY 增长所需的新存储分配失败。
 * @note 尾部已足够时不动；总空间足够时 compact；否则新容量为最低所需容量
 *     与 min(2*旧容量,硬上限) 中的较大值。append 仍不隐式整理或扩容。
 * @note 增长先取得新存储、复制未读字节，再交接并释放旧区；所有失败保持
 *     全部旧存储、容量、索引和 view，不会先 compact 再遇到分配失败。
 * @note 成功（含请求 0 或无需改变的操作）结束全部既有 view，须重新 peek。
 * @note 硬限仅限制当前单区；增长暂存新旧两区，最多 128 MiB 字节请求，
 *     另有对象/分配器开销。内存分配/复制不承诺实时延迟或全局内存预算。
 * @note 线程安全：externally-synchronized；errno：所有路径保持调用前值。
 * @note 不回缩、不改变对象句柄，不执行 I/O、日志或协议校验。
 */
vireo_result_t vireo_buffer_reserve(vireo_buffer_t *buffer, size_t min_tail_space);

/**
 * @brief 显式回缩到指定总容量，完整保留未读字节
 * @param[in,out] buffer 非空存活对象，调用期间独占，所有权不转移。
 * @param[in] capacity 精确目标总容量，正值且 readable_size <= capacity <= 当前容量；
 *     可以低于创建时的初始容量，调用者负责选择复用时机和保留容量。
 * @retval VIREO_OK 当前容量精确等于目标，未读字节顺序/长度保持。
 * @retval VIREO_RESULT_INVALID_ARGUMENT buffer 为 NULL。
 * @retval VIREO_RESULT_RANGE 目标为 0、超过当前容量或不足以容纳未读字节。
 * @retval VIREO_RESULT_NO_MEMORY 严格回缩所需的新存储分配失败。
 * @note 等于当前容量时不分配、不整理；严格变小时先取得新存储、复制未读区，
 *     再提交读索引 0/写索引 readable_size 并释放旧区，不隐式消费或丢数据。
 * @note 空对象仍保留正容量，严格回缩也可能分配失败；所有失败保持全部旧存储、
 *     容量、索引和 view。所有成功（含同容量空操作）结束 view，须重新 peek。
 * @note 不改变对象句柄；换区瞬时同时持有旧区与较小新区，另有分配器/对象开销。
 *     不提供安全擦除、实时延迟、自动回缩或连接高低水位/全局预算控制。
 * @note 线程安全：externally-synchronized；errno：所有路径保持调用前值。
 */
vireo_result_t vireo_buffer_shrink(vireo_buffer_t *buffer, size_t capacity);

#endif /* VIREO_BASE_BUFFER_H */
