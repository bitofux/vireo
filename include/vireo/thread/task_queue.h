/*
 * PROJECT : VIREO
 * FILE    : task_queue.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-11
 * BRIEF   : 固定MPMC队列、非等待交接、资源预算与生命周期合同
 */

#ifndef VIREO_THREAD_TASK_QUEUE_H
#define VIREO_THREAD_TASK_QUEUE_H

#include <vireo/thread/task.h>

#include <stddef.h>
#include <stdint.h>

/**
 * @brief
 *     固定容量条数硬上限，无默认值，容量仍由caller显式提供。
 */
#define VIREO_TASK_QUEUE_MAX_CAPACITY ((size_t)65536)
/**
 * @brief
 *     控制块与固定槽数组的申请字节硬上限，不含task或分配器开销。
 */
#define VIREO_TASK_QUEUE_MAX_ALLOCATION_BYTES ((size_t)67108864)

/**
 * @brief
 *     固定队列的唯一拥有对象，无公共布局或内部槽借用。
 *
 * @note
 *     成功push接管task，成功pop交出最早提交项；不拥有网络或worker。
 *     内部mutex保护MPMC交接和永久关闭，显式prepare后支持worker等待，不执行业务。
 * @note
 *     交接/关闭/inspect thread-safe，owner存储由caller同步；创建/prepare/销毁在共享访问之外。
 *     销毁前结束全部访问，普通指针副本不产生第二所有者或保活。
 *     不冻结 sizeof、私有 ABI、跨线程发布、无锁或硬实时保证。
 */
typedef struct vireo_task_queue vireo_task_queue_t;

/**
 * @brief
 *     显式固定资源选项，没有默认值或自动扩容。
 */
typedef struct vireo_task_queue_options {
    size_t capacity; /**< 正槽位条数，最多65536，允许非2的幂。 */
    size_t max_memory_bytes; /**< 正申请字节预算，最多64MiB，只计容器控制块和槽数组。 */
} vireo_task_queue_options_t;

/**
 * @brief
 *     同一mutex保护的永久接收/领取策略，不描述worker完成状态。
 */
typedef enum vireo_task_queue_state {
    VIREO_TASK_QUEUE_OPEN = 0, /**< 接受提交，普通FIFO领取；创建初态。 */
    VIREO_TASK_QUEUE_DRAIN = 1, /**< 拒绝新提交，允许普通领取剩余项。 */
    VIREO_TASK_QUEUE_CANCEL_PENDING = 2 /**< 拒绝提交/普通领取，只允许专用逐项交还。 */
} vireo_task_queue_state_t;

/**
 * @brief
 *     独立按值数值快照，不返回内部指针或保活资源。
 */
typedef struct vireo_task_queue_info {
    size_t capacity; /**< 创建时固定的槽位条数。 */
    size_t count; /**< 快照时占用项数，0..capacity，不保证下一次try仍相同。 */
    size_t allocated_bytes; /**< 控制块加槽数组实际申请字节数，不含malloc开销或RSS。 */
    size_t max_memory_bytes; /**< 创建时提供的正容器申请预算。 */
    vireo_task_queue_state_t state; /**< 同一快照时点的策略，不表示task已取消或worker结束。 */
    bool wait_prepared; /**< 等待设施已初始化，不表示有等待者。 */
} vireo_task_queue_info_t;

/**
 * @brief
 *     同一受保护时点的独立指标快照，单位为条数或次数，无资源指针。
 *
 * @note
 *     拒绝数只计有效非空push取得锁后的满或关闭拒绝，关闭优先。
 *     参数错误、空源、锁竞争/失败、收尾状态拒绝、领取和观测不计。
 *     计数不重置；恰达到UINT64_MAX仍精确，再计才饱和并置粘性标志。
 */
typedef struct vireo_task_queue_metrics {
    size_t depth; /**< 队列仍拥有的task条数，不含已领取或正在执行项。 */
    size_t high_watermark; /**< 自创建以来已提交push的最大占用条数，初始0。 */
    uint64_t full_rejections; /**< 锁内满队列拒绝次数，最多UINT64_MAX，不回绕。 */
    uint64_t closed_rejections; /**< 锁内关闭拒绝次数，最多UINT64_MAX，不回绕。 */
    bool rejection_count_saturated; /**< 任一累计再次超过可表示范围后永久true。 */
} vireo_task_queue_metrics_t;

/**
 * @brief
 *     受检计算与预算核对后，一次申请并完整初始化固定空槽。
 *
 * @param[in] options
 *     必需稳定可读选项，只借至返回，不保存地址；容量和预算均为正。
 * @param[out] out_queue
 *     必需存活、对齐、可写的独占 owner 地址，入口值须为 NULL。
 *     不与选项、资源或 errno 存储重叠，只借至返回，不保存。
 *
 * @retval VIREO_OK
 *     完整初始化后发布唯一空队列 owner；所有槽为 NULL，count 为0，state为OPEN。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、输出非空、容量或预算为0，整个输出保持。
 * @retval VIREO_RESULT_OVERFLOW
 *     容量乘槽大小或再加控制块无法由 size_t 表示，先于限额判断。
 * @retval VIREO_RESULT_RANGE
 *     容量或预算超硬上限，或实际请求量超过预算，不申请。
 * @retval VIREO_RESULT_NO_MEMORY
 *     申请失败或mutex初始化返回ENOMEM，不发布输出，无残留自有资源。
 * @retval VIREO_RESULT_INTERNAL
 *     mutex初始化返回其他非零直接错误，释放临时原块，不发布。
 *
 * @note
 *     失败保持整个输出及既有资源，所有路径保持入口 errno，无自动重试。
 * @note
 *     预算只计容器请求量，不含 task payload、取消对象或线程栈。
 *     不保证申请成功、非阻塞、进程总内存上限或固定私有控制块大小。
 * @note
 *     创建在共享访问之前，caller负责对象发布和owner存储同步。
 */
vireo_result_t vireo_task_queue_create(vireo_task_queue_options_t const *options,
                                       vireo_task_queue_t **out_queue);

/**
 * @brief
 *     一次尝试内部加锁，返回同一受保护时点的独立数值快照。
 *
 * @param[in] queue
 *     必需存活对象，借至返回；可并发交接/关闭/inspect，不能并发销毁。
 * @param[out] out_info
 *     必需合法独占输出，不与对象或 errno 重叠；不保存地址。
 *
 * @retval VIREO_OK
 *     解锁成功后发布六个逻辑字段，成功不承诺padding。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL，整个输出保持。
 * @retval VIREO_RESULT_BUSY
 *     mutex被占用，一次尝试后返回，整个输出保持。
 * @retval VIREO_RESULT_INTERNAL
 *     加锁或解锁异常，整个输出保持，不承诺同步状态可继续使用。
 * @retval VIREO_RESULT_CANCELLED
 *     cond已消耗的收尾状态，整个输出保持。
 *
 * @note
 *     所有路径保持入口errno；thread-safe，不等待、不自旋，不返回内部指针。
 */
vireo_result_t vireo_task_queue_inspect(vireo_task_queue_t const *queue,
                                        vireo_task_queue_info_t *out_info);

/**
 * @brief
 *     一次trylock观测深度、历史峰值及拒绝累计，不改变策略或任务拥有权。
 *
 * @param[in] queue
 *     必需存活对象，只借至返回；未prepare或已关闭也可观测，不能并发销毁。
 * @param[out] out_metrics
 *     必需独立对齐可写输出，不与queue、errno或其他并发输出存储重叠。
 *     只借至返回，不保存地址，不保活queue或task。
 *
 * @retval VIREO_OK
 *     仅解锁成功后发布五个逻辑字段，不承诺padding或下一次操作时仍相同。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL，优先于收尾状态，整个输出保持。
 * @retval VIREO_RESULT_CANCELLED
 *     cond已消耗的收尾状态，整个输出保持。
 * @retval VIREO_RESULT_BUSY
 *     mutex竞争，一次尝试后返回，整个输出保持。
 * @retval VIREO_RESULT_INTERNAL
 *     其他加锁或解锁异常，整个输出保持，不保证同步可继续使用。
 *
 * @note
 *     thread-safe，不等待、不自旋、不申请、不重置，全部路径保持入口errno。
 *     0 <= depth <= high_watermark <= capacity；领取/关闭不降低历史峰值。
 *     饱和后累计为下界，不产生OVERFLOW或改变原交接结果。
 *     已提交push之后通知/解锁失败仍保峰值；已计拒绝后解锁失败仍保该次计数。
 */
vireo_result_t vireo_task_queue_inspect_metrics(vireo_task_queue_t const *queue,
    vireo_task_queue_metrics_t *out_metrics);

/**
 * @brief
 *     全部访问结束且队列为空时，先销毁存活cond再销毁mutex、释放原块并清空owner。
 *
 * @param[in,out] owner
 *     必需合法独占 owner 地址，在对象之外且不指 errno 存储。
 *     空指针值允许重复销毁；非空值须唯一拥有且没有在途访问。
 *
 * @retval VIREO_OK
 *     释放空容器原块并清NULL；入口空值重复成功，不自动清理task。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     owner 地址 NULL，不改变资源。
 * @retval VIREO_RESULT_BUSY
 *     队列非空或同步销毁返回EBUSY，保留owner、原块及未转出的task。
 * @retval VIREO_RESULT_INTERNAL
 *     同步销毁异常，保留owner和原块，无自动重试。
 *
 * @note
 *     所有路径保持入口 errno，调用前结束全部访问与借用。
 *     按策略先pop或专用取回全部task；BUSY不能允许并发销毁或证明在途结束。
 *     cond销毁失败保持资源；cond成功但mutex失败时，owner只可重试destroy。
 *     此时其他运行入口CANCELLED；不重建cond，重试不会重复销毁cond。
 *     必须先使全部wait_pop返回并结束访问；close本身不能证明worker已退出。
 */
vireo_result_t vireo_task_queue_destroy(vireo_task_queue_t **owner);

/**
 * @brief
 *     本次交接或关闭的同步诊断阶段，不描述任务执行或worker完成。
 */
typedef enum vireo_task_queue_stage {
    VIREO_TASK_QUEUE_STAGE_NONE = 0, /**< 正常路径或基本/满空拒绝，无同步错误。 */
    VIREO_TASK_QUEUE_STAGE_LOCK = 1, /**< trylock竞争或阻塞lock异常。 */
    VIREO_TASK_QUEUE_STAGE_UNLOCK = 2, /**< 获得锁后释放异常，可已有真实交接。 */
    VIREO_TASK_QUEUE_STAGE_WAIT = 3, /**< cond等待失败，未领取。 */
    VIREO_TASK_QUEUE_STAGE_WAKE = 4 /**< 通知失败，可已有提交或关闭。 */
} vireo_task_queue_stage_t;

/**
 * @brief
 *     每路径发布的独立本次进度报告，不含借用资源地址。
 */
typedef struct vireo_task_queue_transfer_report {
    vireo_task_queue_stage_t stage; /**< NONE/LOCK/UNLOCK/WAIT/WAKE，成功为NONE。 */
    bool transferred; /**< 本次是否已经转移task所有权，不等业务完成。 */
    int pthread_error; /**< pthread直接错误，正常为0，不从errno读取。 */
} vireo_task_queue_transfer_report_t;

/**
 * @brief
 *     一次尝试提交唯一task，成功由队列接管且清空调用者owner。
 *
 * @param[in,out] queue
 *     必需存活队列，短借；可并发交接/关闭/inspect，禁止并发销毁。
 * @param[in,out] inout_task
 *     必需合法独占owner地址；非空task须唯一拥有且所有访问/借用已结束。
 *     不保存地址，成功清NULL；同一owner存储不能被并发访问。
 * @param[out] report
 *     必需独立合法输出，只借至返回，每可写路径覆盖三个逻辑字段。
 *
 * @retval VIREO_OK
 *     已提交，源清NULL、transferred=true，按成功提交顺序FIFO领取。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL；有合法report时发布NONE/false/0，owner保持。
 * @retval VIREO_RESULT_NOT_FOUND
 *     源owner为空，优先于尝试锁，未转移。
 * @retval VIREO_RESULT_BUSY
 *     锁竞争或队列满，未转移，源保持；BUSY不能单独证明满。
 * @retval VIREO_RESULT_CANCELLED
 *     已进入仅destroy收尾，或获得锁后已关闭，优先于满表，源保持；空源仍先返回NOT_FOUND。
 * @retval VIREO_RESULT_INTERNAL
 *     同步异常；LOCK未转移，WAKE/UNLOCK按report保留真实转移进度。
 *
 * @note
 *     thread-safe，仅一次trylock、不等待容量或自旋；不承诺公平/无锁/硬实时。
 *     不申请、复制payload、检查期限/取消或执行callback，所有路径保持errno。
 * @note
 *     owner/report须相互独立、不与queue/task资源或errno重叠，不保存地址。
 *     失败除已提交后的WAKE/UNLOCK异常外保持主owner及本调用义务；其他线程可正常推进。
 *     UNLOCK异常不回滚、不自动重试，不承诺同步状态可继续使用；根据实际owner清空
 *     和transferred承担清理责任，源已清空时不可再次提交或释放旧裸别名。
 */
vireo_result_t vireo_task_queue_try_push(vireo_task_queue_t *queue, vireo_task_t **inout_task,
    vireo_task_queue_transfer_report_t *report);

/**
 * @brief
 *     一次尝试领取最早提交task，成功由调用者承担唯一拥有权。
 *
 * @param[in,out] queue
 *     必需存活队列，短借；可并发交接/关闭/inspect，禁止并发销毁。
 * @param[out] out_task
 *     必需独立合法空owner地址，入口须NULL；成功caller用task_destroy释放或转交。
 *     不保存地址，同一owner存储由caller同步，禁止与其他输出或资源重叠。
 * @param[out] report
 *     必需独立合法输出，不与owner/queue/task/errno重叠，每可写路径覆盖。
 *
 * @retval VIREO_OK
 *     最早项已移出，槽清NULL、transferred=true，caller取得唯一task。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL或out_task入口非空，主owner保持。
 * @retval VIREO_RESULT_NOT_FOUND
 *     获得锁后OPEN且为空，主owner保持，不表示以后没有任务。
 * @retval VIREO_RESULT_CANCELLED
 *     仅destroy收尾、CANCEL_PENDING或已排空DRAIN，不转移；不表示已领取worker完成。
 * @retval VIREO_RESULT_BUSY
 *     mutex被占用，一次尝试后返回，主owner保持。
 * @retval VIREO_RESULT_INTERNAL
 *     同步异常；LOCK未转移，UNLOCK可已输出task，按transferred承担真实责任。
 *
 * @note
 *     thread-safe，不等待、不自旋，无入出期申请/业务动作，所有路径保持errno。
 *     FIFO是领取顺序，不保证多个consumer返回或执行完成顺序、公平或硬实时。
 * @note
 *     UNLOCK异常不回滚已移出的task、不自动重试或保证同步状态可继续使用；
 *     输出非空时caller必须保留并清理该owner，不能因返回INTERNAL丢弃。
 *     其他失败保持主owner和本调用义务，报告仍覆盖，其他线程可正常推进。
 */
vireo_result_t vireo_task_queue_try_pop(vireo_task_queue_t *queue, vireo_task_t **out_task,
    vireo_task_queue_transfer_report_t *report);

/**
 * @brief
 *     每路径发布的关闭进度，与task所有权转移分开报告。
 */
typedef struct vireo_task_queue_close_report {
    vireo_task_queue_stage_t stage; /**< NONE/LOCK/UNLOCK/WAKE，正常为NONE。 */
    bool changed; /**< 本次首次OPEN关闭已提交；同模式重复为false，不等当前是否关闭。 */
    int pthread_error; /**< pthread直接错误，正常0，不读取errno。 */
} vireo_task_queue_close_report_t;

/**
 * @brief
 *     一次尝试永久停止接收并选定剩余任务策略，不遍历或等待。
 *
 * @param[in,out] queue
 *     必需存活对象，只借至返回，可并发运行入口，禁止并发销毁。
 * @param[in] mode
 *     只接受DRAIN或CANCEL_PENDING；第一次提交永久生效，不重新开放或换模式。
 * @param[out] report
 *     必需独立合法输出，每可写路径覆盖三个逻辑字段；不保存地址。
 *     不与queue资源、其他输出或errno重叠，caller同步存储。
 *
 * @retval VIREO_OK
 *     首次关闭changed=true；重复同模式changed=false，不改变关闭进度；已prepare时仍广播。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL或非法模式（含OPEN），不关闭，可写报告NONE/false/0。
 * @retval VIREO_RESULT_BUSY
 *     锁竞争，或已关闭为另一模式；本次changed=false，不等待或换模式。
 * @retval VIREO_RESULT_INTERNAL
 *     同步异常，WAKE/UNLOCK时可能changed=true，保留实际已提交关闭。
 * @retval VIREO_RESULT_CANCELLED
 *     cond已消耗的收尾状态，不改变关闭。
 *
 * @note
 *     thread-safe，一次trylock，所有路径保持errno。首次状态提交后不再接受push。
 *     DRAIN保留普通领取；CANCEL_PENDING只允许专用逐项取回，均不清理task。
 * @note
 *     不控制已领取任务、请求共享cancel、执行callback、join或销毁queue。
 *     首次及同模式重复关闭广播；WAKE/UNLOCK异常保持真实关闭，不自动重试。
 *     不承诺同步继续可靠；changed只记录本调用提交。
 */
vireo_result_t vireo_task_queue_close(vireo_task_queue_t *queue, vireo_task_queue_state_t mode,
    vireo_task_queue_close_report_t *report);

/**
 * @brief
 *     CANCEL_PENDING下单项FIFO交还未领取task，由caller显式收尾。
 *
 * @param[in,out] queue
 *     必需存活对象，短借，可并发交接/关闭/inspect，禁止并发销毁。
 * @param[out] out_task
 *     必需独立合法空owner，入口NULL；成功承担唯一拥有，负责释放或转交。
 *     不保存地址，同一存储由caller同步，不与资源、report或errno重叠。
 * @param[out] report
 *     必需独立合法transfer报告，每可写路径覆盖，不保存地址。
 *
 * @retval VIREO_OK
 *     转出最早排队项，槽清NULL、transferred=true；最多一项。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL或输出非空，主owner保持，可写报告NONE/false/0。
 * @retval VIREO_RESULT_BUSY
 *     锁竞争，或状态为OPEN/DRAIN，未转移，不等待或改变策略。
 * @retval VIREO_RESULT_NOT_FOUND
 *     CANCEL_PENDING下已无排队项，不表示已领取worker完成。
 * @retval VIREO_RESULT_INTERNAL
 *     同步异常，UNLOCK可已转出task，保留真实transferred及输出owner。
 * @retval VIREO_RESULT_CANCELLED
 *     cond已消耗的收尾状态，不转移。
 *
 * @note
 *     thread-safe，仅一次trylock，所有路径保持errno，不申请或遍历。
 *     不自动request_cancel/destroy/执行业务，返回对象的取消标志可仍为false。
 * @note
 *     解锁异常不回滚、不重试或保证同步继续可靠；输出非空时必须承担清理责任。
 *     其他失败保持主owner及本调用义务，其他线程仍可合法推进。
 */
vireo_result_t vireo_task_queue_try_take_cancelled(vireo_task_queue_t *queue,
    vireo_task_t **out_task, vireo_task_queue_transfer_report_t *report);

/**
 * @brief
 *     外部排除全部访问后，在空OPEN队列显式准备worker等待设施。
 *
 * @param[in,out] queue
 *     必需存活空OPEN队列；本入口不得与任何对象访问并发。
 *
 * @retval VIREO_OK
 *     cond初始化并发布wait_prepared；同条件重复成功，不重复初始化。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     queue为NULL。
 * @retval VIREO_RESULT_BUSY
 *     非空或非OPEN，不改变资源。
 * @retval VIREO_RESULT_CANCELLED
 *     已进入仅重试destroy的收尾状态。
 * @retval VIREO_RESULT_NO_MEMORY
 *     cond初始化ENOMEM，队列保持。
 * @retval VIREO_RESULT_INTERNAL
 *     cond初始化其他直接错误，队列保持。
 *
 * @note
 *     不额外申请，创建预算已计嵌入控制块；全部路径保持errno，不自动重试。
 */
vireo_result_t vireo_task_queue_prepare_wait(vireo_task_queue_t *queue);

/**
 * @brief
 *     允许等待的worker领取一项；空OPEN等待，醒来循环重检同一mutex内谓词。
 *
 * @param[in,out] queue
 *     必需存活已prepare对象，借至返回，禁止并发prepare或销毁。
 * @param[out] out_task
 *     必需独占空owner地址，成功接管唯一task；不与资源/report/errno重叠。
 * @param[out] report
 *     必需独立输出，每可写路径覆盖三字段；不保存地址。
 *
 * @retval VIREO_OK
 *     按FIFO移出一项，transferred=true，caller负责该task。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL或输出非空，基本校验优先，主owner保持。
 * @retval VIREO_RESULT_NOT_FOUND
 *     尚未prepare，主owner保持。
 * @retval VIREO_RESULT_CANCELLED
 *     CANCEL_PENDING、已排空DRAIN或仅可重试destroy，主owner保持。
 * @retval VIREO_RESULT_INTERNAL
 *     LOCK/WAIT异常未移交；UNLOCK异常可能已移交，不回滚，按report清理。
 *
 * @note
 *     可阻塞mutex和cond，不用于Reactor；无超时、公平或唤醒时限保证。
 *     caller须保证整个调用期间POSIX线程取消已禁用，不接管pthread_cancel。
 *     关闭广播仅改变领取策略，不取消已领取task或证明worker完成。
 * @note
 *     成功push在提交后signal；首次及同模式重复close广播，失败报告WAKE。
 *     通知失败保留真实提交/关闭；UNLOCK异常优先诊断，不承诺同步可继续使用。
 *     所有路径保持errno，无申请、payload复制、期限判断或业务执行。
 *     cond已消耗后的收尾状态使inspect/交接/close/prepare同样返回CANCELLED。
 */
vireo_result_t vireo_task_queue_wait_pop(vireo_task_queue_t *queue, vireo_task_t **out_task,
    vireo_task_queue_transfer_report_t *report);

#endif /* VIREO_THREAD_TASK_QUEUE_H */
