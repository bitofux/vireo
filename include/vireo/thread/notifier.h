/*
 * PROJECT : VIREO
 * FILE    : notifier.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : Linux eventfd 生命周期、一次通知与计数消费
 */
#ifndef VIREO_THREAD_NOTIFIER_H
#define VIREO_THREAD_NOTIFIER_H

#include <stddef.h>
#include <stdint.h>
#include <vireo/base/result.h>

/** 单对象最大用户态申请预算，单位为字节，不含内核资源。 */
#define VIREO_NOTIFIER_MAX_ALLOCATION_BYTES ((size_t)67108864)

/**
 * @brief
 *     唯一拥有一个控制块和一个 Linux eventfd 的 opaque 对象。
 *
 * @note
 *     多 producer 可并发 notify，单 consumer 串行 consume 由 caller 保证；
 *     notify/consume/inspect 可并发，无内部锁，输出独立且指针复制不保活。
 *     caller 同步对象发布与寿命，创建/销毁排除全部访问。
 *     创建、销毁、notify 和 consume 全程由 caller 禁用 POSIX 线程取消；不用于 signal handler，
 *     不支持 fork 后未 exec 复用对象。创建和销毁可能受资源管理影响，不保证非阻塞。
 *     固定非阻塞、close-on-exec，初始计数 0，不使用 EFD_SEMAPHORE。
 *     eventfd 只是提示，不保存 completion 或建立 queue/网络回投；计数不是业务结果数。
 *     不承诺私有布局、sizeof、padding 或跨编译器 ABI。
 */
typedef struct vireo_notifier vireo_notifier_t;

/** 只借至 create 返回，不保存选项地址。 */
typedef struct vireo_notifier_options {
    size_t max_memory_bytes; /**< 显式正预算，最多 64MiB，仅计控制块实际申请字节。 */
} vireo_notifier_options_t;

/** 独立资源快照，不读取内核计数，不保活对象或 fd。 */
typedef struct vireo_notifier_info {
    int fd; /**< 对象唯一拥有的非负 fd，0 合法；输出仅借供未来 Reactor 注册。 */
    size_t allocated_bytes; /**< 实际控制块申请字节，不含内核、malloc 元数据或 RSS。 */
    size_t max_memory_bytes; /**< 创建时提供的正字节预算，后续不跟随 options 变化。 */
} vireo_notifier_info_t;

/** 一次成功通知的独立结果，不保证返回时仍然可读或请求已完成。 */
typedef enum vireo_notifier_notify_outcome {
    VIREO_NOTIFIER_NOTIFY_INCREMENTED = 0, /**< 本次固定的 1 已成功写入计数。 */
    VIREO_NOTIFIER_NOTIFY_ALREADY_PENDING = 1 /**< 写时计数饱和，已有待消费提示，本次未加 1。 */
} vireo_notifier_notify_outcome_t;

/** 本次资源/I/O错误位置，成功及基本参数拒绝为 NONE。 */
typedef enum vireo_notifier_stage {
    VIREO_NOTIFIER_STAGE_NONE = 0, /**< 无资源错误。 */
    VIREO_NOTIFIER_STAGE_ALLOCATE_CONTROL = 1, /**< 用户态控制块申请失败。 */
    VIREO_NOTIFIER_STAGE_CREATE = 2, /**< eventfd 创建失败。 */
    VIREO_NOTIFIER_STAGE_CLOSE = 3, /**< 一次 close 失败，对象仍已消费。 */
    VIREO_NOTIFIER_STAGE_NOTIFY = 4, /**< 一次 write 系统错误或异常返回。 */
    VIREO_NOTIFIER_STAGE_CONSUME = 5 /**< 一次 read 系统错误或异常返回/值。 */
} vireo_notifier_stage_t;

/** 独立按值诊断，不是 owner、重试指令或保活引用。 */
typedef struct vireo_notifier_error {
    vireo_notifier_stage_t stage; /**< 当前错误阶段，每个可写路径覆盖，成功为 NONE。 */
    int system_errno; /**< 对应系统调用的原 errno；成功、参数或用户态分配失败为 0。 */
} vireo_notifier_error_t;

/**
 * @brief
 *     校验固定控制块预算并创建 eventfd，完整成功后发布唯一 owner。
 *
 * @param[in] options
 *     必需存活、对齐、稳定可读选项，正预算不超过 64MiB，只借至返回。
 * @param[out] out_notifier
 *     必需独占可写 owner 地址，入口值须为 NULL，地址不保存。
 * @param[out] out_error
 *     可空独立可写诊断，每路径覆盖；成功及前置拒绝为 NONE/0。
 *
 * @retval VIREO_OK
 *     完整发布拥有控制块及 eventfd 的对象，内核初始计数为 0。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、输出非空或零预算，不取得资源，主输出保持。
 * @retval VIREO_RESULT_RANGE
 *     预算超硬限或小于实际控制块需求，不申请，主输出保持。
 * @retval VIREO_RESULT_NO_MEMORY
 *     用户态申请失败，诊断 ALLOCATE_CONTROL/0，主输出保持。
 * @retval VIREO_RESULT_IO
 *     eventfd 失败，诊断 CREATE/原 errno，配对释放控制块且主输出保持。
 *
 * @note
 *     所有路径保持入口 errno，无默认预算、自动重试或半对象发布。
 *     固定 sizeof 是可表示的 size_t，无变量乘加，不产生算术 OVERFLOW。
 *     内核 ENOMEM 等 eventfd 错误仍为 IO，不等同于用户态申请失败。
 *     eventfd 固定 EFD_NONBLOCK|EFD_CLOEXEC，不使用 EFD_SEMAPHORE。
 *     预算不含内核资源、malloc 元数据、RSS、queue 或 payload。
 * @note
 *     所有地址须合法存活、对齐；输入、输出、诊断、errno 及自有资源互不重叠。
 *     caller 负责同步和发布，整个调用禁用 POSIX 取消；不保存 caller 地址。
 */
vireo_result_t vireo_notifier_create(vireo_notifier_options_t const *options,
    vireo_notifier_t **out_notifier, vireo_notifier_error_t *out_error);

/**
 * @brief
 *     复制三个固定资源字段，不读取或修改 eventfd 内核计数。
 *
 * @param[in] notifier
 *     必需存活对象，只借至返回；可与 notify/consume/inspect 并发，不能并发销毁。
 * @param[out] out_info
 *     必需独占、合法、对齐可写输出，不与对象、输入或 errno 重叠，地址不保存。
 *
 * @retval VIREO_OK
 *     一次发布三个逻辑字段，不承诺 padding。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     任一必需地址 NULL，整个输出保持。
 *
 * @note
 *     全部路径保持 errno，无分配或系统调用；快照不跟随变化、不保活资源。
 *     fd 仅借给未来 Reactor 注册；caller 不 close、dup、改变标志或直接 read/write。
 *     借用仅在对象存活期间有效，数值副本保留不延长寿命，也不检测 fd 复用。
 */
vireo_result_t vireo_notifier_inspect(vireo_notifier_t const *notifier,
    vireo_notifier_info_t *out_info);

/**
 * @brief
 *     一次非阻塞 write 固定的 uint64 值 1，成功发布增量或已有提示结果。
 *
 * @param[in] notifier
 *     必需存活对象，仅借至返回；多 producer 可并发，不能并发创建/销毁。
 * @param[out] out_outcome
 *     必需合法、对齐、独占可写输出，不与其他输入/输出、对象或 errno 重叠。
 * @param[out] out_error
 *     可空独立可写诊断，每路径覆盖，成功含饱和分支为 NONE/0，地址不保存。
 *
 * @retval VIREO_OK
 *     恰写入 8 字节时 INCREMENTED；-1/EAGAIN 时 ALREADY_PENDING，本次未加 1。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL，不执行 write，整个主输出保持。
 * @retval VIREO_RESULT_IO
 *     其他原生 -1 含 EINTR，诊断 NOTIFY/原 errno，整个主输出保持。
 * @retval VIREO_RESULT_INTERNAL
 *     异常原生返回（既非 8 也非 -1），诊断 NOTIFY/0，主输出保持。
 *
 * @note
 *     所有路径保持入口 errno，仅一次 write，无申请、等待容量、自旋或自动重试。
 *     整个调用须由 caller 禁用 POSIX 取消，输出独立，对象发布与寿命由 caller 同步。
 *     ALREADY_PENDING 只描述写时已有可读计数，不保证返回时仍可读。
 *     异常可能已有内核进度，不回滚或承诺计数保持，不自动操作 queue。
 *     不负责 completion 的发布同步或失败清理，不能据此推断完整回投无丢唤醒。
 */
vireo_result_t vireo_notifier_notify(vireo_notifier_t *notifier,
    vireo_notifier_notify_outcome_t *out_outcome, vireo_notifier_error_t *out_error);

/**
 * @brief
 *     一次非阻塞 read 消费累计提示，空计数正常返回 0。
 *
 * @param[in] notifier
 *     必需存活对象，只借至返回；单 consumer 串行此入口，由 caller 保证。
 *     可与 notify/inspect 并发，不能并发创建/销毁。
 * @param[out] out_count
 *     必需合法、对齐、独占可写 uint64 输出，不与对象、输入、诊断或 errno 重叠。
 * @param[out] out_error
 *     可空独立诊断，每路径覆盖，成功含空分支为 NONE/0，地址不保存。
 *
 * @retval VIREO_OK
 *     读到 8 字节非零值时发布原值并已清内核计数；-1/EAGAIN 时发布 0。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL，不执行 read，整个主输出保持。
 * @retval VIREO_RESULT_IO
 *     其他原生 -1 含 EINTR，诊断 CONSUME/原 errno，整个主输出保持。
 * @retval VIREO_RESULT_INTERNAL
 *     异常非 8/-1 返回或成功读到 0，诊断 CONSUME/0，主输出保持。
 *
 * @note
 *     所有路径保持入口 errno，一次 read，无申请、内部 drain 或自动 EINTR 重试。
 *     原生 UINT64_MAX 内核溢出指示保留；不把计数用作完成项数、队列深度或业务序号。
 *     返回 0 仅表示本次观察空，producer 可立即再次通知，不能据此证明 queue 空。
 *     整个调用由 caller 禁用 POSIX 取消；输出独立，对象发布与寿命由 caller 同步。
 *     失败只保证主输出保持，异常可能已消费计数，不回滚或保证内核状态保持。
 */
vireo_result_t vireo_notifier_consume(vireo_notifier_t *notifier,
    uint64_t *out_count, vireo_notifier_error_t *out_error);

/**
 * @brief
 *     全部访问与注册借用结束后，一次 close 并消费对象、清空唯一 owner。
 *
 * @param[in,out] owner
 *     必需独占、合法、对齐可写 owner 地址，值可为 NULL，不保存地址。
 *     所有并发访问及 fd 注册借用须先结束，地址不能在将释放资源或 errno 内。
 * @param[out] out_error
 *     可空独立诊断，不与 owner、errno 或自有资源重叠，每路径覆盖。
 *
 * @retval VIREO_OK
 *     已关闭并释放、清空 owner；入口空 owner 值重复销毁也 OK。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     owner 地址 NULL，诊断 NONE/0，未消费资源。
 * @retval VIREO_RESULT_IO
 *     close 失败，诊断 CLOSE/原 errno；仍释放控制块并清 owner，不重试。
 *
 * @note
 *     所有路径保持入口 errno，整次调用由 caller 禁用 POSIX 取消。
 *     Linux 有效 fd 的 close 错误含 EINTR 仍按已消费处理，旧别名和借用失效。
 *     不重试旧数值 fd，以免作用于复用后的其他资源；不自动清除其他副本。
 *     不负责 queue、worker、网络注销或业务资源，必须先结束所有对象访问。
 */
vireo_result_t vireo_notifier_destroy(vireo_notifier_t **owner,
    vireo_notifier_error_t *out_error);

#endif /* VIREO_THREAD_NOTIFIER_H */
