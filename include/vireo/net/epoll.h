/*
 * PROJECT : VIREO
 * FILE    : epoll.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-02
 * BRIEF   : 此模块负责：
 * -- Linux epoll 实例的唯一所有权与生命周期
 * -- 有界批次工作区和用户态申请预算
 * -- LT 关注项的严格注册、替换与删除
 * -- 一次等待与调用者持有的有界就绪值批次
 */
#ifndef VIREO_NET_EPOLL_H
#define VIREO_NET_EPOLL_H

#include <stddef.h>
#include <stdint.h>
#include <vireo/base/result.h>

/** 单次事件批次位置数的硬上限，不是内核注册数或最大连接数。 */
#define VIREO_EPOLL_MAX_EVENTS ((size_t)65536)
/** 单实例控制块与事件数组的总申请硬上限，64 MiB；不含内核或分配器开销。 */
#define VIREO_EPOLL_MAX_MEMORY ((size_t)67108864)

/** 唯一拥有型实例；内部 fd、数组及布局不公开，不可复制或序列化。 */
typedef struct vireo_epoll vireo_epoll_t;

/** 项目关注位，使用 LT；不是原生 epoll flags，也不是未来就绪结果位。 */
#define VIREO_EPOLL_INTEREST_READ UINT32_C(1)
/** 关注可写；上层应在待发送数据排空后移除此位，避免持续就绪空转。 */
#define VIREO_EPOLL_INTEREST_WRITE UINT32_C(2)
/** 关注对端关闭写侧；不等同本端必须关闭，也不表示接收数据已经读完。 */
#define VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED UINT32_C(4)

/** 注册输入，仅调用期间借用；内核保存数值，不保存本结构体地址。 */
typedef struct vireo_epoll_registration {
    uint32_t interests; /**< 三个项目关注位的任意组合，包括零；未知位非法。 */
    uint64_t token;     /**< 上层解释的不透明值，0..UINT64_MAX 全合法；不是存活证明。 */
} vireo_epoll_registration_t;

/** 就绪输出：可尝试读取，也可能读到 EOF；不保证完整消息。 */
#define VIREO_EPOLL_EVENT_READ UINT32_C(1)
/** 就绪输出：可尝试发送，不保证全部待发送字节被接受。 */
#define VIREO_EPOLL_EVENT_WRITE UINT32_C(2)
/** 就绪输出：对端停止写，接收侧可能仍有未读取字节。 */
#define VIREO_EPOLL_EVENT_PEER_WRITE_CLOSED UINT32_C(4)
/** 就绪输出：内核报告错误，上层须在对应 fd 上确认具体错误。 */
#define VIREO_EPOLL_EVENT_ERROR UINT32_C(8)
/** 就绪输出：内核报告挂断，仍可能有残留可读字节。 */
#define VIREO_EPOLL_EVENT_HANGUP UINT32_C(16)

/** 调用者持有的按值就绪记录，不借用内部数组，也不证明连接存活。 */
typedef struct vireo_epoll_event {
    uint64_t token;  /**< 内核保存的最近一次 ADD/MOD 原值，全 u64 值域合法。 */
    uint32_t events; /**< 五个项目就绪位的组合，独立于注册关注位。 */
} vireo_epoll_event_t;

/** 创建时借用的选项，无默认值，不保存选项地址。 */
typedef struct vireo_epoll_options {
    size_t event_capacity;   /**< 固定批次位置数，1..VIREO_EPOLL_MAX_EVENTS。 */
    size_t max_memory_bytes; /**< 正用户态总申请预算，不超过 VIREO_EPOLL_MAX_MEMORY。 */
} vireo_epoll_options_t;

/** 按值观测，不持有 fd 或数组，不延长对象生命期，不冻结 ABI。 */
typedef struct vireo_epoll_info {
    size_t event_capacity;   /**< 创建时的批次容量，不代表当前有效事件数。 */
    size_t events_bytes;     /**< 完整内部原生事件数组的申请字节数。 */
    size_t allocation_bytes; /**< 控制块加 events_bytes，不是 RSS 或内核内存。 */
    size_t max_memory_bytes; /**< 创建时调用者明确提供的用户态申请预算。 */
} vireo_epoll_info_t;

/** 进程内诊断阶段，不是 wire 编号或重试策略。 */
typedef enum vireo_epoll_stage {
    VIREO_EPOLL_STAGE_NONE = 0,             /**< 成功或前置参数/数值检查，无系统失败。 */
    VIREO_EPOLL_STAGE_ALLOCATE_CONTROL = 1, /**< 控制块分配失败。 */
    VIREO_EPOLL_STAGE_ALLOCATE_EVENTS = 2,  /**< 批次数组分配失败。 */
    VIREO_EPOLL_STAGE_CREATE = 3,           /**< epoll_create1 失败。 */
    VIREO_EPOLL_STAGE_CLOSE = 4,            /**< 实例 close 失败，但对象仍已消费。 */
    VIREO_EPOLL_STAGE_ADD = 5,              /**< epoll_ctl ADD 失败。 */
    VIREO_EPOLL_STAGE_MOD = 6,              /**< epoll_ctl MOD 失败。 */
    VIREO_EPOLL_STAGE_DEL = 7,              /**< epoll_ctl DEL 失败。 */
    VIREO_EPOLL_STAGE_WAIT = 8              /**< 等待系统失败或返回批次违反内部不变量。 */
} vireo_epoll_stage_t;

/** 调用者持有的按值诊断，不含内部指针，不冻结 padding 或序列化布局。 */
typedef struct vireo_epoll_error {
    vireo_epoll_stage_t stage; /**< 本次检测到的失败阶段；成功为 NONE。 */
    int system_errno;         /**< 系统失败的原始 errno；前置检查/用户态 OOM 为 0。 */
} vireo_epoll_error_t;

/**
 * @brief 创建 CLOEXEC epoll 实例与固定批次工作区，全部成功后发布唯一 owner
 * @param[in] options 非 NULL、存活且调用期间稳定的选项，仅借用到返回。
 * @param[in,out] out_epoll 非 NULL、正确对齐且可写的 owner 存储，入口值必须
 *     为 NULL；成功接管对象，最终须用 vireo_epoll_destroy 释放。
 * @param[out] out_error 可为 NULL，否则为独立可写诊断，入口先清空。
 * @retval VIREO_OK 完整取得资源并发布对象，事件容量固定。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需指针为 NULL、owner 非空或数值为零。
 * @retval VIREO_RESULT_OVERFLOW 数组乘法或包含控制块的总量无法由 size_t 表示。
 * @retval VIREO_RESULT_RANGE 容量/预算超过硬限，或总申请需求超过预算。
 * @retval VIREO_RESULT_NO_MEMORY 用户态控制块或数组分配失败。
 * @retval VIREO_RESULT_IO epoll_create1 失败；原始原因见 out_error（包括内核 ENOMEM）。
 * @note 顺序：参数→受检乘法/加法→硬限/预算→两点分配→实例创建→发布。
 *     失败保持 owner，逆序释放已取得内存；不隐式缩小容量或自动重试。
 * @note 所有权：实例 fd 和工作区仅由对象持有，不公开借用；调用者不能
 *     私自 close/dup。工作区未填充，不授予事件读取权；不接管客户端 fd。
 * @note 输入、owner、诊断存储互不重叠；NULL 校验不验证任意地址合法性。
 * @note 线程安全：reactor-only；启动装配可在交接前创建，owner 输出须独占。
 *     没有内部锁，不支持 signal handler、强制取消或 fork 后未 exec 复用对象。
 * @note errno：所有路径保持调用前值；诊断可空，不改变资源处理。
 * @note 预算不含分配器开销、页/RSS、内核实例/watch、连接资源或全局多实例。
 *     不保证分配成功或实时延迟；CLOEXEC 不阻止 fork 继承。
 * @note 本接口不注册或等待事件，不选择触发模式、标识或回调。
 */
vireo_result_t vireo_epoll_create(vireo_epoll_options_t const *options,
                                 vireo_epoll_t **out_epoll,
                                 vireo_epoll_error_t *out_error);

/**
 * @brief 按值读取容量与用户态申请预算，不暴露资源
 * @param[in] epoll 非 NULL、存活对象，仅调用期间借用，所有权保持。
 * @param[out] out_info 非 NULL、正确对齐且可写的独立输出，不与自有资源重叠。
 * @retval VIREO_OK 完整提交四个数值，不改变对象，不表示已有就绪事件。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 任一参数为 NULL，输出全部字节保持。
 * @note 副本不延长实例生命期，不冻结私有控制块/事件的 sizeof 或 ABI。
 * @note 线程安全：reactor-only，须与对象全部访问及销毁协调。
 * @note errno：不读取、不保存且不修改；无分配或系统调用。
 */
vireo_result_t vireo_epoll_inspect(vireo_epoll_t const *epoll,
                                  vireo_epoll_info_t *out_info);

/**
 * @brief 严格添加 LT 关注项，并按值保存 token
 * @param[in] epoll 非 NULL、存活对象，仅调用期间借用，owner 保持。
 * @param[in] fd 非负客户端/其他可监视 fd，0 有效；由上层持有并协调存活。
 * @param[in] registration 非 NULL、存活且调用期间稳定的独立输入，仅借用到返回。
 * @param[out] out_error 可为 NULL，否则为独立可写诊断，入口先清空。
 * @retval VIREO_OK 内核已添加关注项，不表示当前就绪或已有完整消息。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需指针为 NULL、fd 为负或关注位未知；不调用内核。
 * @retval VIREO_RESULT_IO epoll_ctl ADD 失败，诊断为 ADD/原始 errno；重复项为 EEXIST。
 * @note 所有权：不 dup/close 客户端 fd，不修改其阻塞或 CLOEXEC 属性；
 *     registration 地址不保存，token 不解引用，也不检查对应连接是否有效。
 * @note 仅 LT，零关注仍可能收到内核 ERR/HUP；批次容量不是注册数上限。
 *     内核 watch 内存不含在用户态申请预算中，可能 ENOMEM/ENOSPC。
 * @note 输入/诊断/自有资源互不重叠；失败 owner 保持，无用户态注册表或新分配。
 * @note 线程安全：reactor-only，须与同对象全部访问、fd 关闭/复用协调。
 * @note errno：所有路径保持入口值；一次系统调用，不自动重试或转换为 MOD。
 *     本接口不等待、分发、读写字节或管理已返回事件的有效性。
 */
vireo_result_t vireo_epoll_add(vireo_epoll_t *epoll, int fd,
                              vireo_epoll_registration_t const *registration,
                              vireo_epoll_error_t *out_error);

/**
 * @brief 严格替换已有 LT 关注项的全部关注位和 token
 * @param[in] epoll 非 NULL、存活对象，仅调用期间借用，owner 保持。
 * @param[in] fd 非负、由上层持有并协调存活的目标 fd，0 有效。
 * @param[in] registration 非 NULL、存活且稳定的完整新输入，地址仅借用到返回。
 * @param[out] out_error 可空独立可写诊断，入口先清空。
 * @retval VIREO_OK 内核已替换全部关注位和 token，不合并旧关注位。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需指针为 NULL、fd 为负或关注位未知；不调用内核。
 * @retval VIREO_RESULT_IO epoll_ctl MOD 失败，诊断为 MOD/原始 errno；缺失项为 ENOENT。
 * @note 所有权：不保存输入地址、不 dup/close fd、不修改其阻塞/CLOEXEC 属性。
 *     token 全值域且由上层解释，不能证明连接存活；零关注不屏蔽 ERR/HUP。
 * @note 输入/诊断/自有资源互不重叠，失败 owner 保持；无用户态新分配或影子注册表。
 * @note 线程安全：reactor-only，须协调同对象全部访问、fd 关闭与复用。
 * @note errno：所有路径保持入口值；一次调用，不自动重试或转换为 ADD。
 *     只替换内核关注项，不处理已返回批次中的旧事件或执行回调。
 */
vireo_result_t vireo_epoll_mod(vireo_epoll_t *epoll, int fd,
                              vireo_epoll_registration_t const *registration,
                              vireo_epoll_error_t *out_error);

/**
 * @brief 严格移除内核关注项，保持客户端 fd 所有权
 * @param[in] epoll 非 NULL、存活对象，仅调用期间借用，owner 保持。
 * @param[in] fd 非负、由上层持有并协调存活的目标 fd，0 有效。
 * @param[out] out_error 可空独立可写诊断，入口先清空。
 * @retval VIREO_OK 内核关注项已移除，客户端 fd 仍由上层持有。
 * @retval VIREO_RESULT_INVALID_ARGUMENT epoll 为 NULL 或 fd 为负；不调用内核。
 * @retval VIREO_RESULT_IO epoll_ctl DEL 失败，诊断为 DEL/原始 errno；缺失项为 ENOENT。
 * @note 所有权：不 dup/close fd，不修改阻塞/CLOEXEC 属性；无新分配，owner 保持。
 *     诊断不与自有资源重叠；DEL 不清除已经返回到用户工作区的事件副本。
 * @note 生命周期：上层须在 fd 关闭/复用前协调注销和失效处理，不能用旧数值
 *     对新连接重试；dup/fork 的其他引用可能影响内核自动移除行为。
 * @note 线程安全：reactor-only，须协调同对象访问、目标关闭和对象销毁。
 * @note errno：所有路径保持入口值；一次调用，不自动重试或吞掉 ENOENT。
 *     不关闭连接或清理 buffer，不负责服务器停机编排。
 */
vireo_result_t vireo_epoll_del(vireo_epoll_t *epoll, int fd,
                              vireo_epoll_error_t *out_error);

/**
 * @brief 执行一次等待，将有界就绪记录按值交付给调用者
 * @param[in] epoll 非 NULL、存活对象，调用期间借用，owner 保持。
 * @param[in] timeout_ms -1 无限等待，0 立即检查，正数为毫秒；小于 -1 非法。
 * @param[out] out_events 非 NULL、正确对齐且可写的独立数组，实际至少
 *     out_capacity 项；调用者持有，仅本次调用借用，不保存地址。
 * @param[in] out_capacity 正数组容量；本次最多取内部容量与此值的较小值。
 * @param[out] out_count 非 NULL、独立可写数量；成功后仅前 *out_count 项有效。
 * @param[out] out_error 可 NULL，否则为独立可写诊断，入口先清空。
 * @retval VIREO_OK 数量与前 count 项已提交；没有事件亦成功，count 为零。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需指针 NULL、容量零或 timeout_ms < -1；
 *     不调用内核。
 * @retval VIREO_RESULT_IO epoll_wait 失败，包括 EINTR；WAIT/原始 errno。
 * @retval VIREO_RESULT_INTERNAL 原生计数超出本次边界或返回未知原生就绪位；WAIT/0。
 * @note 输出保持：任一失败保持整个 out_events 与 *out_count；成功只写前
 *     count 项和数量，尾部保持。整批检查后才交付，内部工作区允许改写。
 * @note 所有权：不分配用户态内存，不 close/dup 客户端 fd；输出存储由调用者
 *     管理并计入其预算，不含在实例申请预算中。输入/输出与自有资源互不重叠。
 * @note 生命周期：值副本不被后续 wait/MOD/DEL/destroy 自动改写；token 不证明
 *     对应 fd/连接仍有效，不延长其生命期，上层分发前须检查映射和失效。
 * @note 线程安全：reactor-only，无内部锁；等待期间禁止同对象并发访问/销毁，
 *     输出须独占，不支持 signal handler、强制取消或 fork 后未 exec 复用。
 * @note errno：所有路径保持入口值，可空诊断不改变处理；一次系统等待，无
 *     自动重试，EINTR 的继续或停止由上层决定，不以 result 查询自动重试。
 * @note 结果位可组合，ERROR/HANGUP 不要求显式关注；就绪不表示完整消息或
 *     全部 I/O 一定成功。毫秒超时可能因内核粒度/调度略超，不是硬实时 deadline。
 *     -1 不具有限定等待时长；本接口不提供分发、收发、stop 或跨线程 wakeup。
 */
vireo_result_t vireo_epoll_wait(vireo_epoll_t *epoll, int timeout_ms,
                               vireo_epoll_event_t *out_events, size_t out_capacity,
                               size_t *out_count, vireo_epoll_error_t *out_error);

/**
 * @brief 关闭实例并释放工作区，消费及清空唯一 owner
 * @param[in,out] epoll 非 NULL、正确对齐且可写的 owner 存储；*epoll 可为 NULL，
 *     非空时须为尚未销毁的唯一对象，owner 存储不位于被释放资源内。
 * @param[out] out_error 可为 NULL，否则为独立可写诊断，不与 owner/资源重叠。
 * @retval VIREO_OK 已关闭/释放并置 NULL，或入口为空 owner 的成功空操作。
 * @retval VIREO_RESULT_INVALID_ARGUMENT epoll 地址为 NULL。
 * @retval VIREO_RESULT_IO close 失败，诊断保存原始 errno；仍释放并置 NULL。
 * @note 所有权：Linux close 只调用一次，失败含 EINTR 不重试；IO 也消费对象，
 *     全部旧别名失效。不关闭客户端 fd，不执行连接/服务器停机编排。
 * @note 线程安全：reactor-only；先停止全部对象使用，禁止并发销毁或取消。
 * @note errno：所有路径保持调用前值；NULL 诊断不改变清理。
 *     返回 IO 后不得用旧句柄重试；可对空 owner 重复 destroy。
 */
vireo_result_t vireo_epoll_destroy(vireo_epoll_t **epoll,
                                  vireo_epoll_error_t *out_error);

#endif /* VIREO_NET_EPOLL_H */
