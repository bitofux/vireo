/*
 * PROJECT : VIREO
 * FILE    : thread_pool.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 固定 worker 资源、显式放行、任务执行与回收
 */

#ifndef VIREO_THREAD_THREAD_POOL_H
#define VIREO_THREAD_THREAD_POOL_H

#include <stddef.h>
#include <stdbool.h>

#include <vireo/base/result.h>
#include <vireo/thread/task_queue.h>

/**
 * @brief
 *     显式配置的 worker 槽数硬上限，不保证系统线程创建成功。
 */
#define VIREO_THREAD_POOL_MAX_WORKERS ((size_t)256)

/**
 * @brief
 *     容器申请字节硬上限，不含线程栈、队列、task 或 malloc 管理开销。
 */
#define VIREO_THREAD_POOL_MAX_ALLOCATION_BYTES ((size_t)67108864)

/**
 * @brief
 *     唯一拥有固定槽资源及固定 worker 线程的 opaque 对象。
 *
 * @note
 *     start 创建停驻线程；enable_execution 后才领取、执行并清理 task。
 *     同对象管理入口及 owner 存储由 caller 串行同步，worker 自身由内部锁同步。
 *     创建、配置和销毁在外部共享访问之外；销毁前全部已创建线程须成功 join。
 *     裸指针副本不产生第二 owner 或保活；queue/context 借至池销毁。
 *     不冻结 sizeof、私有 ABI；完整停止封装和运行期并发管理策略留后项。
 */
typedef struct vireo_thread_pool vireo_thread_pool_t;

/**
 * @brief
 *     没有默认值或扩容的显式固定资源选项。
 */
typedef struct vireo_thread_pool_options {
    size_t worker_count; /**< 正配置槽数，最多 256，不是活跃线程数。 */
    size_t max_memory_bytes; /**< 正容器申请预算字节数，最多 64 MiB。 */
} vireo_thread_pool_options_t;

/**
 * @brief
 *     放行后由 worker 同步调用的执行入口；装配与 start 不调用它。
 *
 * @param[in,out] context
 *     caller 提供的借用上下文，可 NULL，须存活至 pool 销毁。
 *     多 worker 可同时调用，共享内容及业务资源由 caller 同步。
 * @param[in] task
 *     执行时的必需存活 task，只读借至该次调用返回，不保活。
 *     不得保存地址、修改输入、移动或销毁 task；只能按公开合同观察或借用 payload。
 *
 * @return
 *     本次执行的 vireo_result_t；不是 completion 或线协议状态。
 *
 * @note
 *     返回后借用结束，由 worker 销毁 task；错误记录该 worker 首错，清理后继续领取。
 *     入口须正常返回，不 pthread_exit、longjmp、改变 POSIX 取消状态或重入本池管理。
 *     不访问 Reactor 客户指针或 fd；deadline/cancel 安全点由执行函数按公开合同处理。
 *     本项不回投 completion、不自动重试业务；返回错误不回滚已经发生的业务动作。
 *     context 不归 pool 拥有，配置不提供任意业务数据的跨线程发布保证。
 */
typedef vireo_result_t (*vireo_thread_pool_execute_fn)(void *context,
                                                      vireo_task_t const *task);

/**
 * @brief
 *     单次装配输入；复制三个字段，不保存此结构的地址或转移资源。
 */
typedef struct vireo_thread_pool_configuration {
    vireo_task_queue_t *queue; /**< 必需专用队列，caller 唯一拥有，成功后借至 pool 销毁。 */
    vireo_thread_pool_execute_fn execute; /**< 必需执行入口，放行后才调用。 */
    void *context; /**< 可空长期借用上下文，不由 pool 释放。 */
} vireo_thread_pool_configuration_t;

/**
 * @brief
 *     本次装配的可空独立诊断，不是 pool 运行状态。
 */
typedef enum vireo_thread_pool_configure_stage {
    VIREO_THREAD_POOL_CONFIGURE_STAGE_NONE = 0, /**< 成功、基本错误或重复装配，无队列检查错误。 */
    VIREO_THREAD_POOL_CONFIGURE_STAGE_CHECK_QUEUE = 1 /**< 队列观测错误或资格拒绝。 */
} vireo_thread_pool_configure_stage_t;

/**
 * @brief
 *     本次线程管理错误所在阶段，不是线程池运行状态。
 */
typedef enum vireo_thread_pool_stage {
    VIREO_THREAD_POOL_STAGE_NONE = 0, /**< 成功或基本/资格错误，没有直接 pthread 错误。 */
    VIREO_THREAD_POOL_STAGE_CHECK_QUEUE = 1, /**< 公开队列观测或启动资格检查。 */
    VIREO_THREAD_POOL_STAGE_INIT_MUTEX = 2, /**< 初始化本池互斥锁。 */
    VIREO_THREAD_POOL_STAGE_INIT_CONDITION = 3, /**< 初始化本池条件变量。 */
    VIREO_THREAD_POOL_STAGE_CREATE_WORKER = 4, /**< 创建一个真实 joinable worker。 */
    VIREO_THREAD_POOL_STAGE_LOCK = 5, /**< 管理端或 worker 获取内部锁。 */
    VIREO_THREAD_POOL_STAGE_WAKE = 6, /**< 停止谓词提交后的广播。 */
    VIREO_THREAD_POOL_STAGE_UNLOCK = 7, /**< 管理端或 worker 释放内部锁。 */
    VIREO_THREAD_POOL_STAGE_JOIN_WORKER = 8, /**< 管理端回收一个尚未 join 的线程。 */
    VIREO_THREAD_POOL_STAGE_SET_CANCEL_STATE = 9, /**< worker 入口禁用 POSIX 取消。 */
    VIREO_THREAD_POOL_STAGE_WAIT = 10, /**< worker 停驻等待失败，成功 join 后才可观测。 */
    VIREO_THREAD_POOL_STAGE_TAKE_TASK = 11, /**< 公开队列领取异常，保留原 transfer 报告。 */
    VIREO_THREAD_POOL_STAGE_EXECUTE_TASK = 12 /**< 执行函数返回首个非 OK 结果，不是 pthread 错误。 */
} vireo_thread_pool_stage_t;

/**
 * @brief
 *     独立线程管理报告；错误与实际已发生的资源进度分开。
 *
 * @note
 *     计数是该池累计创建/join 成功条数，不是当前活跃线程数。
 *     cleanup 三字段仅本次 start 失败的停止/join 回收，非 destroy 报告。
 *     基本拒绝仍发布可用 pool 的进度；没有 pool 时四项进度逻辑零。
 */
typedef struct vireo_thread_pool_report {
    vireo_thread_pool_stage_t stage; /**< 当前操作首错；正常/基本拒绝为 NONE。 */
    int pthread_error; /**< 当前直接 pthread 首错，非 pthread 错误为 0。 */
    bool start_attempted; /**< 此池是否已提交唯一一次实际启动尝试。 */
    bool stop_requested; /**< 是否已在锁内提交永久停止谓词，不保证线程已经退出。 */
    size_t created_count; /**< 此池实际 pthread_create 成功累计条数。 */
    size_t joined_count; /**< 此池实际 pthread_join 成功累计条数。 */
    vireo_result_t cleanup_result; /**< 本次启动失败回收的结果，无回收错误为 OK。 */
    vireo_thread_pool_stage_t cleanup_stage; /**< 本次回收首错阶段，正常为 NONE。 */
    int cleanup_pthread_error; /**< 本次回收直接首错，正常为 0。 */
    bool execution_enabled; /**< 已提交一次执行放行，失败也可能已经为 true。 */
    vireo_task_queue_transfer_report_t queue_report; /**< 当前首错为 TAKE_TASK 时的原领取报告，否则逻辑零。 */
} vireo_thread_pool_report_t;

/**
 * @brief
 *     不含内部地址、不保活资源的独立按值快照。
 */
typedef struct vireo_thread_pool_info {
    size_t worker_count; /**< 创建时固定的配置槽数，不表示已经启动 worker。 */
    size_t allocated_bytes; /**< 控制块加固定槽表的实际申请字节数。 */
    size_t max_memory_bytes; /**< 创建时提供的正容器申请预算字节数。 */
    bool configured; /**< 已成功装配 queue 和执行入口，不表示线程已启动。 */
    bool start_attempted; /**< 已提交单次实际启动尝试，失败也不重置。 */
    bool stop_requested; /**< 永久停止谓词已提交，不等全部线程已回收。 */
    size_t created_count; /**< 累计成功创建线程数，最多 worker_count。 */
    size_t joined_count; /**< 累计成功 join 数，最多 created_count。 */
    bool execution_enabled; /**< 已在锁内提交永久放行，不表示任务完成或 worker 健康。 */
} vireo_thread_pool_info_t;

/**
 * @brief
 *     一个成功 join 的 worker 的首错值，不保活线程、task 或池。
 *
 * @note
 *     无错四字段逻辑零；只保存首错，不是逐任务 completion 或全部错误清单。
 *     回调错误后继续处理，后续错误不覆盖首错；只有对应 join 成功后才能查询。
 */
typedef struct vireo_thread_pool_worker_result {
    vireo_result_t result; /**< 该 worker 原始首错；无错为 OK，不把依赖/回调错误统一改为 INTERNAL。 */
    vireo_thread_pool_stage_t stage; /**< 首错阶段；正常 NONE，可为 pthread、TAKE_TASK 或 EXECUTE_TASK。 */
    int pthread_error; /**< 首错的直接 pthread 错误，业务/基本依赖拒绝为 0。 */
    vireo_task_queue_transfer_report_t queue_report; /**< TAKE_TASK 的原 transfer 值，其他首错为逻辑零。 */
} vireo_thread_pool_worker_result_t;

/**
 * @brief
 *     本次提交拒绝或依赖失败所在阶段，独立于原线程管理阶段。
 */
typedef enum vireo_thread_pool_submit_stage {
    VIREO_THREAD_POOL_SUBMIT_STAGE_NONE = 0, /**< 成功或基本参数/空源拒绝。 */
    VIREO_THREAD_POOL_SUBMIT_STAGE_CHECK_POOL = 1, /**< 池运行资格拒绝，未调用队列。 */
    VIREO_THREAD_POOL_SUBMIT_STAGE_SUBMIT_QUEUE = 2 /**< 已调用公开提交，其原结果非 OK。 */
} vireo_thread_pool_submit_stage_t;

/**
 * @brief
 *     本次非等待提交的独立值报告，不拥有或保活 task、queue 或 pool。
 *
 * @note
 *     每可写路径覆盖；未调用队列时嵌套报告逻辑零。
 *     原 transferred 是交接事实，不表示执行成功；非 OK 也可能已经交接。
 */
typedef struct vireo_thread_pool_submit_report {
    vireo_thread_pool_submit_stage_t stage; /**< 本次失败位置，成功为 NONE。 */
    bool queue_called; /**< 是否实际调用一次公开队列提交，不表示交接或完成。 */
    vireo_task_queue_transfer_report_t queue_report; /**< 原队列转移报告，直接错误不写入 errno。 */
} vireo_thread_pool_submit_report_t;

/**
 * @brief
 *     本次关闭与回收的失败位置，独立于原管理和提交阶段。
 */
typedef enum vireo_thread_pool_shutdown_stage {
    VIREO_THREAD_POOL_SHUTDOWN_STAGE_NONE = 0, /**< 成功或基本参数拒绝。 */
    VIREO_THREAD_POOL_SHUTDOWN_STAGE_CHECK_POOL = 1, /**< 池资格拒绝，尚未关闭队列。 */
    VIREO_THREAD_POOL_SHUTDOWN_STAGE_CLOSE_QUEUE = 2, /**< 公开关闭返回非 OK，未调用回收。 */
    VIREO_THREAD_POOL_SHUTDOWN_STAGE_JOIN_WORKERS = 3 /**< 已调用原回收入口，返回其原错误。 */
} vireo_thread_pool_shutdown_stage_t;

/**
 * @brief
 *     关闭与回收两段真实进度，不拥有或保活任何资源。
 *
 * @note
 *     每可写路径发布；未调用的嵌套报告逻辑零，不是当前资源快照。
 *     changed 只表示本次首次关闭提交，joined_count 是原累计成功回收数。
 */
typedef struct vireo_thread_pool_shutdown_report {
    vireo_thread_pool_shutdown_stage_t stage; /**< 本次拒绝或错误位置，正常 NONE。 */
    bool close_called; /**< 是否实际尝试一次公开队列关闭。 */
    vireo_task_queue_close_report_t close_report; /**< 原关闭报告，非 OK 也可能 changed=true。 */
    bool join_called; /**< 是否调用一次原 stop_and_join，不保证所有线程已回收。 */
    vireo_thread_pool_report_t pool_report; /**< 原回收报告，错误也保留全部实际进度。 */
} vireo_thread_pool_shutdown_report_t;

/**
 * @brief
 *     受检预算后一次申请、完整初始化未启动槽资源，再发布唯一 owner。
 *
 * @param[in] options
 *     必需稳定可读选项，正槽数与正预算，仅借至返回，不保存地址。
 * @param[out] out_pool
 *     必需存活、对齐、可写的独占 owner 地址，入口值须为 NULL。
 *
 * @retval VIREO_OK
 *     成功发布唯一空池；有固定槽资源，但没有已创建的线程。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、零配置或创建目标非空。
 * @retval VIREO_RESULT_OVERFLOW
 *     槽表乘法或控制块加法不可表示，优先于硬限与预算检查。
 * @retval VIREO_RESULT_RANGE
 *     槽数或预算超出硬限，或者预算小于受检申请量。
 * @retval VIREO_RESULT_NO_MEMORY
 *     实际分配返回 NULL，没有发布资源或启动线程。
 *
 * @note
 *     失败保持整个主输出和既有资源；所有路径保持入口 errno。
 *     容器预算不含线程栈、queue、task、取消对象、malloc 元数据或 RSS。
 *     malloc 可能耗时，不承诺非阻塞、实际线程可启动或最佳 worker 数。
 *     输入、输出、资源与 errno 存储不得非法重叠；悬空或伪造地址不可检测。
 */
vireo_result_t vireo_thread_pool_create(vireo_thread_pool_options_t const *options,
                                        vireo_thread_pool_t **out_pool);

/**
 * @brief
 *     公开核验专用队列后，单次保存未来执行所需的借用关联。
 *
 * @param[in,out] pool
 *     必需存活未装配对象；同对象与 owner 访问由 caller 同步。
 * @param[in] configuration
 *     必需稳定可读配置，仅借至返回；queue 与 execute 必须非 NULL。
 *     queue 须专用一个 pool、OPEN、已 prepare 且为空，context 可 NULL。
 * @param[out] stage
 *     可空独立可写诊断，只借至返回；每可写路径覆盖，成功为 NONE。
 *
 * @retval VIREO_OK
 *     三字段副本与 configured 已完整发布，没有启动线程或调用执行入口。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL 或执行函数为空，优先于重复和队列检查。
 * @retval VIREO_RESULT_BUSY
 *     pool 已装配、队列非空，或公开 inspect 返回锁竞争。
 * @retval VIREO_RESULT_CANCELLED
 *     本池仅可重试销毁，或观测队列已关闭，或公开 inspect 返回仅可销毁状态。
 * @retval VIREO_RESULT_NOT_FOUND
 *     观测队列尚未 prepare；关闭检查优先，非空检查随后。
 * @retval VIREO_RESULT_INTERNAL
 *     公开 inspect 返回同步异常，原错误透传，stage 为 CHECK_QUEUE。
 *
 * @note
 *     configure 期间 caller 必须排除 queue 的其他访问，保证观测到发布间条件不变。
 *     基本错误、仅可重试销毁和重复装配 stage 为 NONE；队列观测或资格失败为 CHECK_QUEUE。
 *     不申请、不自动 prepare、排空、关闭或重试；失败保持 pool 和 queue 的逻辑状态
 *     与本调用借用义务。同步异常不保证依赖内部同步仍健康；所有路径保持入口 errno。
 * @note
 *     成功后 queue/context 借至 pool 销毁返回，caller 保证目标存活及专用性；
 *     不保存 owner 地址、不接管其拥有权。原配置结构返回后可以改变。
 *     没有 reset 或重装配；销毁 pool 不关闭 queue、不释放 context 或 queue 中的 task。
 * @note
 *     配置、stage、pool/queue 内部资源和 errno 不得非法重叠；caller 保证地址有效。
 *     外部同步不等管理入口运行期 thread-safe；放行后执行；并发管理/完整停止封装留后项。
 */
vireo_result_t vireo_thread_pool_configure(vireo_thread_pool_t *pool,
    vireo_thread_pool_configuration_t const *configuration,
    vireo_thread_pool_configure_stage_t *stage);

/**
 * @brief
 *     短借存活池，发布九个逻辑字段的独立快照。
 *
 * @param[in] pool
 *     必需存活对象，仅借至返回；同对象访问由 caller 同步。
 * @param[out] out_info
 *     必需存活、对齐、可写且不与输入、内部资源或 errno 非法重叠的地址。
 *
 * @retval VIREO_OK
 *     发布配置、预算、装配与累计启动/停止/join 进度；不返回线程句柄。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     任一必需地址为 NULL。
 * @retval VIREO_RESULT_CANCELLED
 *     销毁已消耗条件变量而互斥锁仍待释放，仅允许重试 destroy。
 *
 * @note
 *     失败保持整个输出；所有路径保持入口 errno。
 *     快照不保活对象，也不随它改变，资源销毁后快照数值仍可读。
 */
vireo_result_t vireo_thread_pool_inspect(vireo_thread_pool_t const *pool,
                                         vireo_thread_pool_info_t *out_info);

/**
 * @brief
 *     全部线程成功 join 且外部访问结束后释放本池资源，清空唯一 owner。
 *
 * @param[in,out] owner
 *     必需存活、对齐、可写的独占 owner 地址；入口指针值允许 NULL。
 *
 * @retval VIREO_OK
 *     资源已释放且 owner 清空；空指针值重复销毁也成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     owner 地址为 NULL。
 * @retval VIREO_RESULT_BUSY
 *     仍有未成功 join 的线程，或同步资源销毁直接返回 EBUSY。
 * @retval VIREO_RESULT_INTERNAL
 *     同步资源销毁返回其他直接错误；保留 owner，不从 errno 取错误。
 *
 * @note
 *     创建与销毁在共享访问之外，销毁前结束对 pool 的全部访问及借用。
 *     不自动停止或 join，不允许并发销毁试探 worker 是否结束。
 *     先销毁已初始化条件变量，再销毁互斥锁；若后一步失败，保留 owner，
 *     仅可重试 destroy，不重建或再次销毁条件变量。
 *     结束 pool 对 queue/context 的借用，不关闭或释放它们，也不清理排队 task。
 *     失败保持 owner 和尚未释放资源，已完成的同步资源释放不回滚。
 *     所有路径保持入口 errno。
 */
vireo_result_t vireo_thread_pool_destroy(vireo_thread_pool_t **owner);

/**
 * @brief
 *     单次启动固定真实 worker，保持停驻，直到显式放行或请求停止。
 *
 * @param[in,out] pool
 *     必需已配置存活池，管理访问外部串行同步，不可处于仅重试销毁阶段。
 * @param[out] report
 *     必需独立可写报告，每可写路径发布，不与资源或 errno 非法重叠。
 *
 * @retval VIREO_OK
 *     配置数的 pthread_create 全部成功；不保证 worker 已进入等待或没有入口错误。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL。
 * @retval VIREO_RESULT_NOT_FOUND
 *     尚未配置，或公开观测发现 queue 尚未 prepare。
 * @retval VIREO_RESULT_BUSY
 *     已提交过实际启动尝试，或公开 queue 观测竞争。
 * @retval VIREO_RESULT_CANCELLED
 *     仅可重试销毁，或 queue 已关闭。
 * @retval VIREO_RESULT_NO_MEMORY
 *     初始化返回 ENOMEM，或创建线程返回 EAGAIN。
 * @retval VIREO_RESULT_INTERNAL
 *     其他直接 pthread 错误或依赖同步错误。
 *
 * @note
 *     queue 公开观测错误原样返回；成功观测后检查 OPEN 再检查 prepared，允许非空。
 *     caller 在资格检查期间排除 queue 其他访问，queue/context 借用合同保持。
 *     start 只用于启动管理流程，可能在失败回收时等待，不允许 Reactor 服务轮调用。
 *     caller 整调用禁用 POSIX 取消；worker 入口也禁用，不 detach 或 pthread_cancel。
 *     资格拒绝不消耗启动尝试；开始初始化后永久不能重新 start，须收尾销毁重建。
 * @note
 *     先初始化内嵌 mutex/cond 再逐项创建；无需额外 heap，线程栈不计容器预算。
 *     创建失败保原首错，主动停止并尝试 join 已创建部分，回收错误独立报告。
 *     唤醒/解锁未确认成功时不盲目 join，保剩余句柄和 owner，不保证损坏同步恢复。
 *     初始化标志、已停止和成功 join 进度保留，不回滚或自动重试；全部 errno 保持。
 */
vireo_result_t vireo_thread_pool_start(vireo_thread_pool_t *pool,
                                       vireo_thread_pool_report_t *report);

/**
 * @brief
 *     在已确认的队列关闭后，停止停驻等待并逐项 join 尚未回收的 worker。
 *
 * @param[in,out] pool
 *     必需存活池，管理访问外部串行同步，不得从本池 worker 或并发管理调用。
 * @param[out] report
 *     必需独立可写十一字段报告，每可写路径发布。
 *
 * @retval VIREO_OK
 *     所有已创建线程成功回收；已回收重复调用也 OK，不重复 join。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL。
 * @retval VIREO_RESULT_NOT_FOUND
 *     尚未提交实际启动尝试。
 * @retval VIREO_RESULT_CANCELLED
 *     仅可重试销毁。
 * @retval VIREO_RESULT_BUSY
 *     已放行而 queue 仍 OPEN，或公开观测竞争；本次不提交停止或 join。
 * @retval VIREO_RESULT_INTERNAL
 *     本次停止/join 直接异常，或成功 join 后发现 worker 的同步首错。
 * @return
 *     依赖或执行函数的其他首错原样返回，报告真实已回收进度；不是业务回滚。
 *
 * @note
 *     可能阻塞，仅用于关闭管理流程，不可在 Reactor 服务轮运行；caller 全程禁用 POSIX 取消。
 *     不持内部锁进行 join；每项未回收线程本次最多 join 一次，一项失败仍处理其他项。
 *     成功 join 后才读取 worker 自身错误，记录本次首错和真实累计计数；不重试失败项。
 *     未确认广播和解锁成功时不进入 join；报告已提交停止，保留全部剩余资源。
 *     未放行仍只回收停驻线程，queue 不变。放行后 caller 必须先成功公开 close
 *     为 DRAIN 或 CANCEL_PENDING（含必要的成功同模式再次广播），再调用本入口。
 *     核对 queue 已关闭后才提交本池停止；状态快照不能证明失败广播已经恢复。
 *     DRAIN 继续领取剩余项；CANCEL_PENDING 未领取项由 caller 显式取回清理。
 *     已领取的执行函数须正常返回；不自动 close、请求 cancel、清理业务或释放 pool。
 *     首错按本次 join 遍历顺序选择，不保证跨 worker 的全局时间先后；
 *     已全部回收重复 OK，不再次返回历史 worker 错误，可另查询保留的首错值。
 *     所有路径保持 errno；同步损坏不保证可恢复，不盲目重试或重启。
 */
vireo_result_t vireo_thread_pool_stop_and_join(vireo_thread_pool_t *pool,
                                               vireo_thread_pool_report_t *report);


/**
 * @brief
 *     全部线程创建成功后，一次放行其公开队列领取与任务执行。
 *
 * @param[in,out] pool
 *     必需存活、完整启动、未停止、未放行池；管理访问由 caller 串行同步。
 * @param[out] report
 *     必需独立十一字段报告，每可写路径发布，真实放行可能先于同步报错。
 *
 * @retval VIREO_OK
 *     锁内放行已提交且广播/解锁成功，不保证 worker 已开始或没有执行错误。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL。
 * @retval VIREO_RESULT_NOT_FOUND
 *     没有实际启动尝试，或公开观测发现 queue 尚未 prepare。
 * @retval VIREO_RESULT_BUSY
 *     已放行、未完整创建或已 join 任一线程，或公开 queue 观测竞争。
 * @retval VIREO_RESULT_CANCELLED
 *     已请求停止、仅可销毁，或观测 queue 已关闭。
 * @retval VIREO_RESULT_INTERNAL
 *     本池同步或公开观测异常；依赖原错误透传。
 *
 * @note
 *     先基本/retiring/启动/停止/完整性检查，再公开核验 OPEN/prepared，再 lock 放行。
 *     caller 在公开资格观测期间排除 queue 的其他访问，放行后正常使用队列同步。
 *     不申请额外资源；锁内只置永久 flag/广播，不持锁领取、执行或销毁 task。
 *     放行后广播/解锁失败保留 flag，不能重新放行；须明确关闭 queue 并收尾，
 *     不保证损坏同步健康。可能等待管理锁，不用于 Reactor 服务轮，全程禁 POSIX 取消。
 *     callback 仅借用 task，正常返回后 worker 通过公开 destroy 清理唯一 owner；
 *     回调错误记录后继续，队列异常按真实 owner 清理后退出，不重试依赖或业务。
 *     不自动检查 deadline/cancel，不提供 completion；所有路径保持入口 errno。
 */
vireo_result_t vireo_thread_pool_enable_execution(vireo_thread_pool_t *pool,
    vireo_thread_pool_report_t *report);

/**
 * @brief
 *     仅对应线程成功 join 后，取得该 worker 持久的首错值。
 *
 * @param[in] pool
 *     必需存活池，管理访问串行同步，不能处于仅可重试销毁阶段。
 * @param[in] worker_index
 *     数值槽索引，0..worker_count-1；不返回或使用线程句柄。
 * @param[out] out_result
 *     必需独立可写四字段值，失败保持整个输出，只借至返回，不保活资源。
 *
 * @retval VIREO_OK
 *     发布首错或无错值；out_result.result 可非 OK，不影响查询本身成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL，优先于其他拒绝。
 * @retval VIREO_RESULT_CANCELLED
 *     池处于仅可重试销毁阶段。
 * @retval VIREO_RESULT_RANGE
 *     槽索引越界。
 * @retval VIREO_RESULT_NOT_FOUND
 *     此槽从未成功创建线程。
 * @retval VIREO_RESULT_BUSY
 *     此槽尚未成功 join；不能据线程看似结束提前读取。
 *
 * @note
 *     只有 join 建立该 worker 写入的观察顺序，不额外申请或锁定，也不重试。
 *     全部路径保持入口 errno；成功只保证逻辑字段，不保证 padding。
 *     不是运行期进度、全部错误或逐请求完成报告；对应 worker 首错不会被重复收尾清除。
 */
vireo_result_t vireo_thread_pool_inspect_worker_result(vireo_thread_pool_t const *pool,
    size_t worker_index, vireo_thread_pool_worker_result_t *out_result);

/**
 * @brief
 *     检查已放行池的运行资格，再一次尝试交出唯一 task，不等待容量。
 *
 * @param[in,out] pool
 *     必需存活池，只借至返回；同池提交和其他管理入口由 caller 串行同步。
 *     worker 可以正常并发领取；不得从本池执行回调重入管理入口。
 * @param[in,out] task_owner
 *     必需独占可写 owner 地址，入口 task 必须由 caller 唯一拥有且借用已结束。
 *     成功交接清源；地址仅借至返回，不保存，普通指针副本不保活或增加拥有权。
 * @param[out] report
 *     必需独立可写三字段报告，每可写路径发布，不与 owner、资源或 errno 非法重叠。
 *
 * @retval VIREO_OK
 *     已交接给队列，源为 NULL；不保证 worker 健康、回调成功或任务执行完成。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL，优先于空源和运行资格拒绝。
 * @retval VIREO_RESULT_NOT_FOUND
 *     源 task 为空，或池尚未配置/尚未实际启动；空源优先池资格检查。
 * @retval VIREO_RESULT_CANCELLED
 *     池仅可重试销毁/已请求停止，或公开队列提交拒绝已关闭队列。
 * @retval VIREO_RESULT_BUSY
 *     未完整创建、尚未放行、已有成功 join，或公开队列满/锁竞争。
 * @retval VIREO_RESULT_INTERNAL
 *     公开队列提交同步异常；保留其原诊断及实际所有权转移。
 * @return
 *     队列依赖其他错误原样返回，不自动清理、回滚或重试。
 *
 * @note
 *     基本检查后依次为空源、retiring/停止、配置/启动、完整创建/放行/未 join。
 *     池拒绝 stage 为 CHECK_POOL；基本或空源拒绝为 NONE，不调用队列。
 *     资格通过后只调用一次公开 try_push，不额外 inspect 或获取池锁。
 *     依赖非 OK stage 为 SUBMIT_QUEUE，成功为 NONE；queue_called 如实记录调用。
 *     未转移失败保持源；通知或解锁异常可能已转移，源仍 NULL、原 transferred=true。
 *     worker 可能在返回前已经执行并销毁 task，交接后不得访问旧裸指针或再次释放。
 * @note
 *     内部不申请、复制 payload、等待容量、自旋或重试；不保证 lock-free 或硬实时。
 *     caller 用串行调用满足池管理同步，不能在 Reactor 服务轮新增可能等待的外部锁。
 *     不允许与 start/enable/stop/destroy 等池管理同时调用，也不认证 worker 当前性。
 *     不自动检查 deadline/cancel、不提供 completion、业务或网络动作。
 *     其他线程仍可合法改变队列；报告不是全局冻结快照。所有路径保持入口 errno。
 */
vireo_result_t vireo_thread_pool_try_submit(vireo_thread_pool_t *pool,
    vireo_task_t **task_owner, vireo_thread_pool_submit_report_t *report);

/**
 * @brief
 *     完整放行池先选定队列关闭策略，关闭成功后回收 worker。
 *
 * @param[in,out] pool
 *     必需存活、完整创建并已放行的池，只借至返回；管理访问由 caller 串行同步。
 *     允许已停止或部分/全部成功 join，不能处于仅可重试销毁阶段。
 * @param[in] mode
 *     只接受公开 DRAIN 或 CANCEL_PENDING；永久模式，不允许升级或重新开放。
 * @param[out] report
 *     必需独立可写五字段报告，每可写路径发布；不与资源或 errno 非法重叠。
 *
 * @retval VIREO_OK
 *     本次公开关闭及原回收均成功；CANCEL_PENDING 仍可能保留待 caller 清理的任务。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL 或非法模式（含 OPEN），优先池资格检查。
 * @retval VIREO_RESULT_NOT_FOUND
 *     尚未配置或没有实际启动尝试。
 * @retval VIREO_RESULT_BUSY
 *     未完整创建、未放行、公开关闭锁竞争/模式冲突，或原回收依赖观测竞争。
 * @retval VIREO_RESULT_CANCELLED
 *     池或其队列处于仅可重试销毁阶段，或依赖返回原取消结果。
 * @retval VIREO_RESULT_INTERNAL
 *     原关闭/回收同步异常；保留原阶段、直接错误和已发生的关闭/join 进度。
 * @return
 *     原回收的其他依赖或 worker 首错原样返回，非 OK 也可能已经全部 join。
 *
 * @note
 *     基本检查后为 retiring、配置/实际启动、完整创建/放行资格；不拒绝已有 join。
 *     资格通过后一次公开 close，只有 OK 才一次原 stop_and_join，不另观测或内部重试。
 *     关闭非 OK 立即返回、不 join，即使 changed=true；不能仅凭关闭已提交假设唤醒可靠。
 *     基本拒绝 stage NONE，池资格 CHECK_POOL，依赖失败为 CLOSE_QUEUE/JOIN_WORKERS。
 *     成功 stage NONE；未调用嵌套报告逻辑零，只看对应 called 才能解释进度。
 * @note
 *     同模式再调用仍先 close 一次，可能 BUSY；原回收只尝试未 join 线程。
 *     全部已 join 后原回收重复 OK，不重新上报历史首错，仍可查询原 worker_result。
 *     未放行或部分启动失败使用原 stop_and_join，不自动放行；不回滚真实进度。
 *     不申请、请求共享取消、领取 pending、销毁 task/queue/pool 或释放长期借用。
 *     CANCEL_PENDING 剩余任务由 caller 用公开队列入口逐项取回并清理。
 * @note
 *     可能等待管理锁、回调正常返回和 join，只用于允许阻塞的关闭管理流程。
 *     caller 整调用禁用 POSIX 取消；不 pthread_cancel/detach，不保证有限等待或损坏同步恢复。
 *     禁止同池并发管理/提交或从本池执行回调重入；worker 可以并发合法领取。
 *     必须全部 join 且结束借用后才能销毁依赖，不用于 Reactor 服务轮。
 *     所有路径保持入口 errno；直接 pthread 错误保留在原报告，不通过 errno 推断。
 */
vireo_result_t vireo_thread_pool_shutdown_and_join(vireo_thread_pool_t *pool,
    vireo_task_queue_state_t mode, vireo_thread_pool_shutdown_report_t *report);

#endif
