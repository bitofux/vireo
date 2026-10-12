/*
 * PROJECT : VIREO
 * FILE    : completion_queue.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 固定 MPSC 完成队列、显式资源预算与唯一 owner 交接
 */

#ifndef VIREO_THREAD_COMPLETION_QUEUE_H
#define VIREO_THREAD_COMPLETION_QUEUE_H

#include <vireo/thread/completion.h>

/** 最大固定槽数，单位为条；不是默认容量或吞吐量保证。 */
#define VIREO_COMPLETION_QUEUE_MAX_CAPACITY ((size_t)65536)
/** 单容器最大申请预算，单位为字节，不含完成对象及其响应数据。 */
#define VIREO_COMPLETION_QUEUE_MAX_ALLOCATION_BYTES ((size_t)67108864)

/**
 * @brief
 *     唯一拥有控制块、固定槽数组及已提交 completion 的 opaque 容器。
 *
 * @note
 *     多个 producer 可并发 push，单 consumer 串行 pop 由 caller 保证。
 *     内部默认非 robust mutex；try/close/inspect 一次 try，wait_push 允许阻塞。
 *     创建/销毁排除全部访问；寿命、共享 owner 存储和跨线程发布由 caller 同步。
 *     指针副本不保活；等待须先显式 prepare，close 永久拒绝提交并广播，保留已入队结果。
 *     cond 已销毁而 mutex 销毁失败后，仅可重试 destroy，不得继续运行。
 *     不承诺私有布局、sizeof、二进制表示或未来新增字段后的申请量不变。
 */
typedef struct vireo_completion_queue vireo_completion_queue_t;

/** 显式创建选项，只借至创建返回，不保存选项地址。 */
typedef struct vireo_completion_queue_options {
    size_t capacity; /**< 正槽数，最多 65536，允许非 2 的幂，无默认或扩容。 */
    size_t max_memory_bytes; /**< 正容器申请预算，最多 64MiB，不含 completion payload。 */
} vireo_completion_queue_options_t;

/** 独立数值快照，不返回内部地址或保活容器。 */
typedef struct vireo_completion_queue_info {
    size_t capacity; /**< 创建时固定的槽数，单位为条。 */
    size_t count; /**< 观测时队列拥有的完成项数，范围 0..capacity。 */
    size_t allocated_bytes; /**< 控制块加槽数组的实际申请字节数，不含 malloc 开销/RSS。 */
    size_t max_memory_bytes; /**< 创建时提供的正容器预算，单位为字节。 */
    bool closed; /**< 观测时提交端是否已永久关闭；不表示排空或访问结束。 */
    bool wait_prepared; /**< 观测时是否拥有已初始化等待设施，不表示有线程正在等待。 */
} vireo_completion_queue_info_t;

/** 同 mutex 采样的独立指标；不表示 worker 在途、吞吐或访问结束。 */
typedef struct vireo_completion_queue_metrics {
    size_t depth; /**< 采样时队列拥有的完成项数，单位为条，0..capacity。 */
    size_t high_watermark; /**< 从创建起已提交占用峰值，depth..capacity，不随领取下降。 */
    uint64_t full_rejections; /**< 有效 try_push 锁内因满被拒的累计；wait_push 的等待不计。 */
    uint64_t closed_rejections; /**< 有效 try_push/wait_push 锁内因关闭被拒的累计，每调用最多一次。 */
    bool rejection_count_saturated; /**< 至少一个累计在 MAX 后再被计数，永久为 true，累计成为下界。 */
} vireo_completion_queue_metrics_t;

/**
 * @brief
 *     一次 try 观测当前深度、历史峰值及实际容量/关闭拒绝累计。
 *
 * @param[in] queue
 *     必需存活容器，只借至返回；允许与提交、领取、关闭并发，不能并发销毁。
 * @param[out] out_metrics
 *     必需存活、对齐、独占可写输出，不与 queue、其他输入输出或 errno 重叠。
 *     地址只借至返回，不保存；值独立，不保活或跟随后续变化。
 *
 * @retval VIREO_OK
 *     成功解锁后一次发布五个逻辑字段，不承诺 padding。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL，优先于收尾检查，整个输出保持。
 * @retval VIREO_RESULT_CANCELLED
 *     已进入仅重试 destroy 的收尾终态，整个输出保持。
 * @retval VIREO_RESULT_BUSY
 *     一次 try 加锁竞争，整个输出保持。
 * @retval VIREO_RESULT_INTERNAL
 *     其他加锁或解锁直接异常，整个输出保持，不自动重试。
 *
 * @note
 *     全部路径保持入口 errno；复用原 mutex，不申请、等待容量、重置或导出指标。
 *     初始深度、峰值、累计为 0，标志 false；两种实际提交均更新峰值。
 *     拒绝仅有效非空提交取得锁后计数，关闭优先满；满等待、参数错误、空源、
 *     未准备、锁竞争/失败、等待异常、收尾拒绝、领取及观测不计。
 *     已提交或已拒绝后的解锁异常仍保留真实指标及 owner 进度。
 *     累计恰达 UINT64_MAX 仍精确，再计保持 MAX 并永久置饱和标志，不回绕。
 *     饱和不改变交接原结果或归属；无指标重置，无等待时长或公平保证。
 */
vireo_result_t vireo_completion_queue_inspect_metrics(vireo_completion_queue_t const *queue,
    vireo_completion_queue_metrics_t *out_metrics);

/**
 * @brief
 *     受检计算并核对预算，完整初始化固定空槽后发布唯一容器 owner。
 *
 * @param[in] options
 *     必需稳定可读选项，只借至返回；容量和预算均为正，不保存地址。
 * @param[out] out_queue
 *     必需存活、对齐、可写的独占 owner 地址，入口值须为 NULL。
 *     不与 options、资源或 errno 存储重叠，只借至返回，不保存地址。
 *
 * @retval VIREO_OK
 *     完整发布空容器，全部槽为 NULL，count 为 0，closed/wait_prepared 为 false。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、创建输出非空、容量或预算为 0，输出保持。
 * @retval VIREO_RESULT_OVERFLOW
 *     容量乘槽大小或再加控制块不可由 size_t 表示，先于限额判断。
 * @retval VIREO_RESULT_RANGE
 *     容量/预算超硬上限，或实际申请量超过预算，不申请。
 * @retval VIREO_RESULT_NO_MEMORY
 *     申请或 mutex 初始化返回 ENOMEM，不发布半对象，配对回滚。
 * @retval VIREO_RESULT_INTERNAL
 *     其他 mutex 初始化异常，不发布并配对回滚。
 *
 * @note
 *     失败保持整个主输出、输入及既有资源，所有路径保持入口 errno，无自动重试。
 * @note
 *     创建在发布之前，跨线程发布和寿命由 caller 保证。
 *     申请可受系统内存管理影响，不保证非阻塞或全进程内存上限。
 * @note
 *     预算仅含控制块及固定槽数组，不含 completion、线程栈、malloc 元数据或 RSS。
 */
vireo_result_t vireo_completion_queue_create(vireo_completion_queue_options_t const *options,
    vireo_completion_queue_t **out_queue);

/**
 * @brief
 *     在一次 try 加锁成功后复制六字段独立快照。
 *
 * @param[in] queue
 *     必需存活对象，只借至返回，允许与交接并发，不能并发销毁。
 * @param[out] out_info
 *     必需合法独占输出，不与容器或 errno 重叠，不保存地址。
 *
 * @retval VIREO_OK
 *     发布原五字段及 wait_prepared 共六个逻辑字段。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     任一必需地址 NULL，整个输出保持。
 * @retval VIREO_RESULT_CANCELLED
 *     cond 已消耗的收尾终态，仅允许重试 destroy，输出保持。
 *
 * @note
 *     一次 try 加锁，竞争返回 BUSY，其他加锁/解锁异常 INTERNAL。
 *     只有成功解锁才发布整个输出；所有失败保持输出。
 *     所有路径保持 errno；无申请，不承诺输出 padding。
 *     快照独立于后续资源寿命，不跟随变化，不返回槽或结果指针。
 */
vireo_result_t vireo_completion_queue_inspect(vireo_completion_queue_t const *queue,
    vireo_completion_queue_info_t *out_info);

/**
 * @brief
 *     在全部访问结束后释放自有空容器并清空唯一 owner。
 *
 * @param[in,out] owner
 *     必需合法独占 owner 地址，值可 NULL；销毁前结束全部访问和借用。
 *     不与资源或 errno 重叠，不保存地址，其他裸指针副本不会自动清零。
 *
 * @retval VIREO_OK
 *     配对释放整个自有块并清 owner，空 owner 值重复销毁也返回 OK。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     owner 地址 NULL，资源保持。
 *
 * @note
 *     所有路径保持入口 errno；caller 排除全部并发访问，不由内部锁保活。
 *     非空返回 BUSY，不自动清理 completion、业务资源或 caller 上下文。
 *     prepared 空容器先销毁 cond，再销毁 mutex，EBUSY 返回 BUSY，其他异常 INTERNAL。
 *     cond 失败保资源；cond 已消耗而 mutex 失败则保 owner 和剩余资源，仅可重试 destroy。
 *     不重复销毁 cond 或重建等待设施；未 prepared 时仍只销毁 mutex。
 */
vireo_result_t vireo_completion_queue_destroy(vireo_completion_queue_t **owner);

/** 本次交接的同步失败位置，正常满/空也为 NONE。 */
typedef enum vireo_completion_queue_transfer_stage {
    VIREO_COMPLETION_QUEUE_TRANSFER_NONE = 0, /**< 本次没有同步异常。 */
    VIREO_COMPLETION_QUEUE_TRANSFER_LOCK = 1, /**< 一次 try 加锁未取得锁。 */
    VIREO_COMPLETION_QUEUE_TRANSFER_UNLOCK = 2, /**< 已取得锁后的解锁异常。 */
    VIREO_COMPLETION_QUEUE_TRANSFER_WAIT = 3, /**< 满队列条件等待异常，未提交源。 */
    VIREO_COMPLETION_QUEUE_TRANSFER_WAKE = 4 /**< 领取已提交后通知空间异常，不回滚交接。 */
} vireo_completion_queue_transfer_stage_t;

/** 独立历史报告，不拥有或保活已经转出的结果。 */
typedef struct vireo_completion_queue_transfer_report {
    vireo_completion_queue_transfer_stage_t stage; /**< 同步失败位置，成功为 NONE。 */
    bool transferred; /**< 本次是否已提交唯一 owner 交接，报错时也可能为 true。 */
    int pthread_error; /**< pthread 原错误码，普通满/空/基本错误为 0。 */
} vireo_completion_queue_transfer_report_t;

/**
 * @brief
 *     尝试提交一个独占完成对象，FIFO 按成功提交顺序。
 *
 * @param[in,out] queue
 *     必需存活队列，多个 producer 可并发使用，禁止并发销毁。
 * @param[in,out] owner
 *     必需独占 owner 地址，值为 caller 唯一拥有的非空 completion。
 *     全部对象操作和借用已结束；同一 owner 存储不得并发使用。
 * @param[out] out_report
 *     必需独立可写报告，与 owner、资源和 errno 不重叠，所有可写路径发布。
 *
 * @retval VIREO_OK
 *     已清源并交给队列，不表示执行、消费或发送完成。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL；可写报告为 NONE/false/0。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空源，先于加锁检查，不转移。
 * @retval VIREO_RESULT_BUSY
 *     一次 try 加锁竞争（LOCK/EBUSY）或已锁定后满表（NONE/0），不转移。
 * @retval VIREO_RESULT_CANCELLED
 *     有效非空源取得锁后发现永久关闭，先于满表判定，保持源不转移。
 *     或 cond 已消耗的收尾终态，不转移。
 * @retval VIREO_RESULT_INTERNAL
 *     其他加锁或解锁异常，报告原错误，按 transferred 判断实际交接。
 *
 * @note
 *     无申请、复制、核验客户/期限或自动重试。未交接保源；交接后解锁失败不回滚。
 *     每次最多一次 try 加锁，没有无锁、公平或硬实时保证；全部路径保持 errno。
 *     输出地址只借至返回，不保存；资源寿命与 owner 唯一性由 caller 保证。
 */
vireo_result_t vireo_completion_queue_try_push(vireo_completion_queue_t *queue,
    vireo_completion_t **owner, vireo_completion_queue_transfer_report_t *out_report);

/**
 * @brief
 *     单 consumer 尝试领取最早提交的一项，转出唯一 owner。
 *
 * @param[in,out] queue
 *     必需存活队列，caller 保证所有 pop 串行，允许与 producer 并发。
 * @param[out] out_completion
 *     必需独占空 owner 地址；成功交给 caller，后续处理及配对销毁由 caller 负责。
 * @param[out] out_report
 *     必需独立报告，与 owner、资源和 errno 不重叠，每可写路径发布。
 *
 * @retval VIREO_OK
 *     已领取最早项，transferred 为 true。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL 或领取输出非空，不转移。
 * @retval VIREO_RESULT_NOT_FOUND
 *     已锁定后 OPEN 队列为空，不转移，报告 NONE/false/0。
 * @retval VIREO_RESULT_CANCELLED
 *     已锁定后队列关闭且为空，不转移；关闭但有项仍正常领取。
 *     或 cond 已消耗的收尾终态，不转移。
 * @retval VIREO_RESULT_BUSY
 *     一次 try 加锁竞争，报告 LOCK/false/EBUSY。
 * @retval VIREO_RESULT_INTERNAL
 *     其他同步异常；交接后解锁异常仍保留非空输出和 transferred=true。
 *     prepared 队列领取后 signal 失败报告 WAKE，仍保真实转移；UNLOCK 异常优先。
 *
 * @note
 *     失败且未交接保持 owner；已交接不回滚，不自动清理。所有路径保持 errno。
 *     不申请、复制、判断客户/期限或等待；输出地址只借至返回，不保活队列。
 */
vireo_result_t vireo_completion_queue_try_pop(vireo_completion_queue_t *queue,
    vireo_completion_t **out_completion, vireo_completion_queue_transfer_report_t *out_report);

/** 本次 close 的同步失败位置，独立于交接报告的枚举。 */
typedef enum vireo_completion_queue_close_stage {
    VIREO_COMPLETION_QUEUE_CLOSE_NONE = 0, /**< 本次没有同步异常。 */
    VIREO_COMPLETION_QUEUE_CLOSE_LOCK = 1, /**< 一次 try 加锁未取得锁。 */
    VIREO_COMPLETION_QUEUE_CLOSE_UNLOCK = 2, /**< 已取得锁后的解锁异常。 */
    VIREO_COMPLETION_QUEUE_CLOSE_WAKE = 3 /**< 已关闭后的广播异常，保真实 changed。 */
} vireo_completion_queue_close_stage_t;

/** 本调用的独立历史关闭报告，不保活队列。 */
typedef struct vireo_completion_queue_close_report {
    vireo_completion_queue_close_stage_t stage; /**< 同步失败位置，成功为 NONE。 */
    bool changed; /**< 本次首次关闭是否已提交；不是当前 closed 值。 */
    int pthread_error; /**< pthread 原直接错误码，无同步异常时 0。 */
} vireo_completion_queue_close_report_t;

/**
 * @brief
 *     永久停止新提交，保留已入队结果供单消费者继续 FIFO 领取。
 *
 * @param[in,out] queue
 *     必需存活队列，只借至返回；允许与 producer、consumer 和观测并发。
 *     不能并发销毁，寿命由 caller 保证，不保存 caller 指针地址。
 * @param[out] out_report
 *     必需存活、对齐、独占可写报告，每可写路径覆盖。
 *     不与 queue、owner、其他输入输出或 errno 存储重叠，不保存地址。
 *
 * @retval VIREO_OK
 *     提交端已永久关闭；首次 changed=true，重复 changed=false，不重新开放。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL；可写报告为 NONE/false/0，队列不因本调用改变。
 * @retval VIREO_RESULT_BUSY
 *     一次 try 加锁竞争，报告 LOCK/false/EBUSY，本调用未提交关闭。
 * @retval VIREO_RESULT_INTERNAL
 *     其他加锁或解锁异常，报告原码；解锁异常保留已发生关闭及真实 changed。
 *     prepared 时广播异常报告 WAKE，UNLOCK 异常优先，不撤销关闭。
 * @retval VIREO_RESULT_CANCELLED
 *     cond 已消耗的收尾终态，仅允许重试 destroy，不改变关闭状态。
 *
 * @note
 *     不申请、遍历、取消或销毁 completion，不改变队列数量或已领取结果。
 *     有效非空 push 在锁内观察关闭后 CANCELLED 保源，关闭优先满表。
 *     已入队仍正常 pop；关闭且空返回 CANCELLED，不代表所有 producer 已退出。
 *     destroy 仍要求全部访问结束且为空，空 OPEN 或关闭队列均可销毁。
 *     与交接复用默认非 robust mutex，每次只 try 一次；无自旋、等待或自动重试。
 *     已提交关闭不因解锁异常回滚，不承诺损坏同步恢复，所有路径保持入口 errno。
 *     prepared 时首次和重复 close 均广播所有等待者，无唤醒时限保证。
 */
vireo_result_t vireo_completion_queue_close(vireo_completion_queue_t *queue,
    vireo_completion_queue_close_report_t *out_report);

/**
 * @brief
 *     外部排除全部访问后，在空 OPEN 队列显式准备生产者等待设施。
 *
 * @param[in,out] queue
 *     必需存活空 OPEN 队列，不得与任何访问并发，只借至返回。
 *
 * @retval VIREO_OK
 *     已初始化 cond 并发布 wait_prepared，同条件重复成功且不重复初始化。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     queue 为 NULL。
 * @retval VIREO_RESULT_BUSY
 *     队列非空或已永久关闭，不改变资源。
 * @retval VIREO_RESULT_CANCELLED
 *     cond 已消耗的收尾终态，仅可重试 destroy。
 * @retval VIREO_RESULT_NO_MEMORY
 *     cond 初始化 ENOMEM，资源保持，可后续显式再调用。
 * @retval VIREO_RESULT_INTERNAL
 *     cond 初始化其他直接错误，资源保持。
 *
 * @note
 *     不额外申请，创建时的显式预算已包含内嵌等待存储；所有路径保持 errno。
 *     不自动重试、开启线程或改变闭锁/FIFO，不接管 POSIX 线程取消。
 */
vireo_result_t vireo_completion_queue_prepare_wait(vireo_completion_queue_t *queue);

/**
 * @brief
 *     允许等待的 worker 在有空槽时提交一项，满 OPEN 队列循环等待并重检。
 *
 * @param[in,out] queue
 *     必需存活已 prepare 队列，只借至返回，禁止并发 prepare 或销毁。
 * @param[in,out] owner
 *     必需独占非空 completion 源，caller 唯一拥有，全部操作和借用已结束。
 *     同一 owner 存储不得并发使用；未转移时仍由 caller 清理或选择后续动作。
 * @param[out] out_report
 *     必需合法独立报告，每可写路径发布，不与资源、owner 或 errno 重叠。
 *
 * @retval VIREO_OK
 *     提交已发生，清源并由队列唯一接管，不保证已被消费或发送。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL，基本校验优先，不转移。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空源优先，或尚未 prepare，不转移。
 * @retval VIREO_RESULT_CANCELLED
 *     收尾终态，或已 prepare 后锁内发现永久关闭，关闭优先容量，保源。
 * @retval VIREO_RESULT_INTERNAL
 *     LOCK/WAIT 异常未提交；UNLOCK 异常可能已提交，按 transferred 承担义务。
 *
 * @note
 *     可阻塞取得 mutex 和等待 cond，无超时、公平或等待时限保证，不用于 Reactor。
 *     caller 须保证整个调用期间 POSIX 线程取消已禁用，不使用 pthread_cancel 终止等待。
 *     满且 OPEN 时 cond_wait，醒来重新持锁并循环检查，唤醒不预留槽。
 *     每次成功 pop 通知一个等待者；首次及重复 close 广播全部，返回后 source 仍可能非空。
 * @note
 *     无申请、复制 payload、客户/期限核验或自动清理，不保存 caller 地址。
 *     未提交保源，已提交后的解锁异常不回滚；所有路径保持 errno。
 *     close 不证明等待者已返回；必须结束全部访问后才能 destroy，不保证损坏同步恢复。
 */
vireo_result_t vireo_completion_queue_wait_push(vireo_completion_queue_t *queue,
    vireo_completion_t **owner, vireo_completion_queue_transfer_report_t *out_report);

#endif /* VIREO_THREAD_COMPLETION_QUEUE_H */
