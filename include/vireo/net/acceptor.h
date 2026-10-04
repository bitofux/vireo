/*
- PROJECT : VIREO
- FILE    : acceptor.h
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 预配置监听 socket 的验证、唯一所有权转移与销毁
- -- 固定控制申请预算、按值观察和错误诊断
- -- 有界接入批次与新客户端 fd 的唯一所有权交接
- -- 单 loop 借用、READ 开关与回调在途生命周期保护
 */
#ifndef VIREO_NET_ACCEPTOR_H
#define VIREO_NET_ACCEPTOR_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <vireo/base/result.h>
#include <vireo/net/event_loop.h>

/** 控制对象的显式申请预算硬限，64 MiB；不是内核或整个 server 的限额。 */
#define VIREO_ACCEPTOR_MAX_MEMORY ((size_t)67108864)

/** 单轮成功接入与调用者 fd 数组容量硬限；不是全 server 的客户总限额。 */
#define VIREO_ACCEPTOR_MAX_BATCH ((size_t)65536)

/** 唯一拥有型监听对象，全部入口 Reactor-only，布局不公开。 */
typedef struct vireo_acceptor vireo_acceptor_t;

/** 按值读取的显式选项，不保存地址，没有默认值。 */
typedef struct vireo_acceptor_options {
    size_t max_memory_bytes; /**< 1..MAX_MEMORY，至少容纳实际控制申请。 */
} vireo_acceptor_options_t;

/** 按值资源快照，不包含监听 fd 或其他借用，不延长对象生命期。 */
typedef struct vireo_acceptor_info {
    size_t allocation_bytes; /**< 唯一固定控制对象的实际申请。 */
    size_t max_memory_bytes; /**< 创建时提供的显式预算。 */
    bool loop_attached;      /**< 本地仍保留绑定；不证明外部 loop 存活。 */
    bool callback_active;    /**< 业务回调在途；self-detach 不提前结束它。 */
    bool read_enabled;       /**< 成功提交的 READ 关注开关；无绑定时 false。 */
} vireo_acceptor_info_t;

/** 本层阶段，不作为 wire 状态或 fd 所有权的替代。 */
typedef enum vireo_acceptor_stage {
    VIREO_ACCEPTOR_STAGE_NONE = 0,             /**< 成功或参数/容量/属性拒绝。 */
    VIREO_ACCEPTOR_STAGE_VALIDATE_FD = 1,      /**< fd 查询失败或返回不变量异常。 */
    VIREO_ACCEPTOR_STAGE_ALLOCATE_CONTROL = 2, /**< 控制对象分配失败。 */
    VIREO_ACCEPTOR_STAGE_CLOSE_LISTENER = 3,   /**< 单次 close 失败。 */
    VIREO_ACCEPTOR_STAGE_ACCEPT_CLIENT = 4     /**< 单次 accept4 的不可跳过 IO。 */
} vireo_acceptor_stage_t;

/** 按值诊断，无资源所有权；所有路径保持调用入口 errno。 */
typedef struct vireo_acceptor_error {
    vireo_acceptor_stage_t stage; /**< 结果来源阶段。 */
    int system_errno;            /**< IO 的原 errno，其他分类为 0。 */
} vireo_acceptor_error_t;

/**
 * @brief 验证预配置监听 fd，在完整初始化后接管并发布对象
 *
 * @param[in] options
 *     非空有效选项，仅调用期间借用。
 * @param[in,out] fd_owner
 *     非空独立唯一 fd owner 地址；入口非负，0 合法，成功置 -1。
 * @param[in,out] out_acceptor
 *     非空独立拥有者地址，入口必须为 NULL，成功交给 destroy。
 * @param[out] error
 *     可空独立诊断，非空时每次覆盖 stage/system_errno。
 *
 * @retval VIREO_OK
 *     已取得一个固定控制对象并接管原监听 fd，两 owner 完整提交。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需指针空、对象 owner 非空、fd 为负、预算为零，或成功查询后属性不符。
 * @retval VIREO_RESULT_RANGE
 *     预算超过硬限或小于实际控制申请需求。
 * @retval VIREO_RESULT_NO_MEMORY
 *     控制对象分配失败；没有接管或关闭输入 fd。
 * @retval VIREO_RESULT_IO
 *     fcntl/getsockopt 查询失败，诊断保留原 errno，不自动重试。
 * @retval VIREO_RESULT_INTERNAL
 *     成功查询的输出长度违反预期；没有接管输入 fd。
 *
 * @note 输入须已配置 O_NONBLOCK、FD_CLOEXEC、SOCK_STREAM 且 SO_ACCEPTCONN 为真；
 *     不额外限制地址家族。只查询，不改变属性、不 dup、不 socket/bind/listen 或解析地址。
 *     不 accept、不登记 loop，不把监听 fd 当成已连接客户 fd。
 * @note 顺序：参数/预算→F_GETFL→F_GETFD→SO_TYPE→SO_ACCEPTCONN→分配/初始化→发布。
 *     任一步失败保持两 owner；调用者仍负责原输入 fd，不需要本层回滚关闭。
 * @note fd 须未被外部登记，不能并发使用、更改、关闭或保留其他 owner；查询不证明这些前置。
 *     成功后旧整数别名不授予再次 close/修改/登记权，复制对象句柄不复制所有权。
 * @note 预算只含控制申请，不包含分配器开销、内核 socket/队列、客户连接或 RSS/全局限额；
 *     不为预算上限预分配字节，也不保证分配成功或性能。
 * @note 所有指针存活、正确对齐、互不重叠且独立，不位于自有资源内。NULL 检查不验证坏地址。
 *     Reactor-only；不支持 signal handler、异步取消或 fork 后 exec 前操作。保持入口 errno。
 */
vireo_result_t vireo_acceptor_create(vireo_acceptor_options_t const *options,
                                    int *fd_owner, vireo_acceptor_t **out_acceptor,
                                    vireo_acceptor_error_t *error);

/**
 * @brief 读取固定申请、预算与绑定状态，不公开监听 fd 或端点借用
 *
 * @param[in] acceptor
 *     非空存活对象，仅调用期间借用，所有权保持。
 * @param[out] out_info
 *     非空独立可写数值输出，不与对象资源重叠。
 *
 * @retval VIREO_OK
 *     完整按值提交资源快照，不改变对象。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     任一指针 NULL；输出全部字节保持。
 *
 * @note 无分配或系统调用；副本不延长对象生命期，不冻结私有布局或 ABI。
 *     Reactor-only，保持入口 errno，不验证外部违反所有权前置造成的 fd 损坏。
 */
vireo_result_t vireo_acceptor_inspect(vireo_acceptor_t const *acceptor,
                                     vireo_acceptor_info_t *out_info);

/**
 * @brief 单次关闭监听 fd，释放控制对象并消费唯一 owner
 *
 * @param[in,out] acceptor
 *     非空独立唯一 owner 地址，*acceptor 可为 NULL；先结束全部同对象使用。
 * @param[out] error
 *     可空独立诊断，每次覆盖。
 *
 * @retval VIREO_OK
 *     已关闭并释放、owner 置 NULL，或空 owner 重复成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     owner 地址 NULL。
 * @retval VIREO_RESULT_BUSY
 *     仍绑定或回调在途，全部 owner/资源保持，不 close/free。
 * @retval VIREO_RESULT_IO
 *     单次 close 失败，仍释放控制并置 NULL；保留原 errno，不重试旧 fd。
 *
 * @note 成功与 IO 均结束旧句柄借用/别名，返回 IO 不意味着 owner 仍存活。
 *     先成功 detach（或满足 forget 前置），再等待当前回调/全部使用结束；不自动 DEL。
 *     不负责清理已交出的客户或其他对象，不支持外部登记或并发使用。
 *     Reactor-only，所有路径保持入口 errno，不保证修复损坏对象或违约测试 hooks。
 */
vireo_result_t vireo_acceptor_destroy(vireo_acceptor_t **acceptor,
                                     vireo_acceptor_error_t *error);

/** 每轮显式双预算，按值借用，无默认值或时间上限。 */
typedef struct vireo_acceptor_accept_budget {
    size_t max_accepts;  /**< 正成功数上限，不超过 MAX_BATCH。 */
    size_t max_syscalls; /**< 任意正 size_t；包含成功、可跳错误、空队列与 IO 尝试。 */
} vireo_acceptor_accept_budget_t;

/** 只报告本轮观察到的停止点，不保证队列已空或其他客户不存在。 */
typedef enum vireo_acceptor_accept_stop {
    VIREO_ACCEPTOR_ACCEPT_BATCH_FULL = 1,  /**< 成功数达到预算和数组容量较小值。 */
    VIREO_ACCEPTOR_ACCEPT_CALL_BUDGET = 2, /**< 尚有输出空间，但调用次数达到预算。 */
    VIREO_ACCEPTOR_ACCEPT_WOULD_BLOCK = 3, /**< 实际 accept4 返回 EAGAIN/EWOULDBLOCK。 */
    VIREO_ACCEPTOR_ACCEPT_IO_ERROR = 4     /**< 不可跳过 IO，可能已有成功接入。 */
} vireo_acceptor_accept_stop_t;

/** 本轮按值进度；合法操作 OK/IO 均提交，不拥有任何 fd。 */
typedef struct vireo_acceptor_accept_info {
    size_t accepted_count;                  /**< 已转移至 caller 数组的成功前缀长度。 */
    size_t accept_calls;                    /**< 本轮实际单次 accept4 尝试数。 */
    size_t transient_errors;                /**< 已计入调用预算的可跳接入错误数。 */
    vireo_acceptor_accept_stop_t stop_reason; /**< 实际停止原因，容量优先于调用预算。 */
} vireo_acceptor_accept_info_t;

/**
 * @brief 按双预算接入客户端，把新 fd 逐个转移到调用者空 owner 数组
 *
 * @param[in,out] acceptor
 *     非空存活监听对象，借用到本次返回，所有权保持。
 * @param[in] budget
 *     非空独立正预算；max_accepts 不超过 MAX_BATCH，max_syscalls 任意正值。
 * @param[in,out] fd_owners
 *     非空独立可写 int 数组，具有 capacity 个有效元素；成功前缀成为唯一 fd owner。
 * @param[in] capacity
 *     1..MAX_BATCH；仅前 min(max_accepts, capacity) 个元素须全为 -1。
 * @param[out] out_info
 *     必需独立进度输出，OK/IO 都完整提交，参数拒绝保持全部字节。
 * @param[out] error
 *     可空独立诊断，每次覆盖；IO 为 ACCEPT_CLIENT/原 errno，其他分类 NONE/0。
 *
 * @retval VIREO_OK
 *     批次满、调用预算耗尽或实际 EAGAIN/EWOULDBLOCK，已提交本轮进度。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需指针 NULL、任一预算/容量为零，或受检输出前缀含非 -1 元素。
 * @retval VIREO_RESULT_RANGE
 *     max_accepts 或 capacity 超过 MAX_BATCH。
 * @retval VIREO_RESULT_IO
 *     EINTR 或其他不可跳过 accept4 错误；此前成功 fd/真实统计仍提交。
 *
 * @note accept4 使用 SOCK_NONBLOCK|SOCK_CLOEXEC，不取得 peer 地址、不 fallback accept。
 *     fd=0 合法；监听 fd 保持，新客户 fd 不由 acceptor 缓存或拥有，不改变旧接口属性。
 * @note ECONNABORTED、ENETDOWN、EPROTO、ENOPROTOOPT、EHOSTDOWN、ENONET、
 *     EHOSTUNREACH、EOPNOTSUPP、ENETUNREACH 计入 transient_errors 后有界继续下一次；
 *     EINTR 和其他错误立即 IO，不重试。所有尝试计入 max_syscalls。
 * @note 每次尝试前按批次满→调用预算顺序检查，不越过边界多探查一次队列。
 *     参数拒绝不 accept，保持整个数组和 info；合法操作只改成功前缀，其他元素保持。
 * @note IO 不回滚或关闭已交出 fd；调用者须接管或单次 close 每个成功元素。
 *     listener destroy 不消费这些客户。EMFILE 等恢复、connection/pool/loop 接线留上层。
 * @note 无用户态运行期分配、回调或指针保存；内核客户 socket/fd 不计控制预算。
 *     所有存储有效、正确对齐、独立且互不重叠，不位于对象自有资源。
 * @note Reactor-only；结束本次调用才可销毁 listener，不支持 signal handler、异步取消、
 *     外部并发或 fork 后 exec 前操作。所有路径恢复入口 errno，次数预算不保证硬实时。
 */
vireo_result_t vireo_acceptor_accept_batch(vireo_acceptor_t *acceptor,
                                          vireo_acceptor_accept_budget_t const *budget,
                                          int *fd_owners, size_t capacity,
                                          vireo_acceptor_accept_info_t *out_info,
                                          vireo_acceptor_error_t *error);

/**
 * 业务通知仅借用对象，不自动 accept；事件为 loop 已过滤的 READ/ERROR/HANGUP。
 * 可观察、显式有界 accept、开关 READ 或 self-detach；代码/context 须活到正常返回。
 * 不可在途 destroy/重新 attach，不可 longjmp、强制取消或破坏对象/独立输出。
 */
typedef void (*vireo_acceptor_callback_t)(vireo_acceptor_t *acceptor,
                                         uint32_t events, void *context);

/** 绑定操作的独立阶段，不覆盖资源或接入诊断。 */
typedef enum vireo_acceptor_loop_stage {
    VIREO_ACCEPTOR_LOOP_STAGE_NONE = 0,   /**< 成功或本层前置拒绝。 */
    VIREO_ACCEPTOR_LOOP_STAGE_ATTACH = 1, /**< 公共 ADD 非成功。 */
    VIREO_ACCEPTOR_LOOP_STAGE_UPDATE = 2, /**< 公共 MOD 非成功。 */
    VIREO_ACCEPTOR_LOOP_STAGE_DETACH = 3  /**< 公共 DEL 非成功。 */
} vireo_acceptor_loop_stage_t;

/** 独立按值诊断；完整保留 public loop/epoll 原因，成功/本层拒绝全成员为零。 */
typedef struct vireo_acceptor_loop_error {
    vireo_acceptor_loop_stage_t stage; /**< 本项失败操作阶段。 */
    vireo_event_loop_error_t loop_error; /**< 完整原诊断，不以入口 errno 判断失败。 */
} vireo_acceptor_loop_error_t;

/**
 * @brief 将 listener 借给单个 loop，完整 ADD 成功后保存业务绑定
 *
 * @param[in,out] acceptor
 *     非空存活唯一对象，listener/control 所有权保持。
 * @param[in,out] loop
 *     非空存活借用对象，存活至成功 DEL 或符合整体清理前置。
 * @param[in] read_enabled
 *     true 关注 READ，false 零关注；零关注仍可能 ERROR/HANGUP。
 * @param[in] callback
 *     非空固定借用代码，注册结束且在途执行返回前保持存活。
 * @param[in] context
 *     可空固定借用上下文，期限同 callback，不由本对象释放。
 * @param[out] error
 *     可空独立诊断，全部存储有效/对齐/互不重叠，不位于自有资源。
 *
 * @retval VIREO_OK
 *     一次 ADD 成功，绑定发布；未调用业务代码或接入客户。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需对象或 callback 空；依赖前置拒绝原样返回。
 * @retval VIREO_RESULT_BUSY
 *     已绑定或当前回调在途，或依赖注册表满/重复 fd；保持状态。
 * @retval VIREO_RESULT_OVERFLOW
 *     依赖身份发放耗尽。
 * @retval VIREO_RESULT_IO
 *     ADD 失败，保持全部本地状态与资源，保留完整原诊断。
 *
 * @note fd/handle 隐藏；不得外部更改此注册、关闭 fd 或提前结束代码/context 借用。
 *     loop 不拥有 listener；本层不拥有 loop，不改其注册容量，不自动 accept/close。
 * @note 整体 loop 销毁后 forget 前仅 inspect/forget/受保护 destroy，不能访问悬空 loop；
 *     本层无法自动验证 loop 生命期。直接 accept_batch 在绑定/READ 暂停时仍允许。
 * @note Reactor-only，无本层运行期分配/重试，保持入口 errno；不支持信号/异步取消。
 */
vireo_result_t vireo_acceptor_attach(vireo_acceptor_t *acceptor, vireo_event_loop_t *loop,
                                    bool read_enabled, vireo_acceptor_callback_t callback,
                                    void *context, vireo_acceptor_loop_error_t *error);

/**
 * @brief 严格一次 MOD，将当前绑定的 READ 关注替换为 READ 或零
 *
 * @param[in,out] acceptor
 *     非空已绑定对象，所属 loop 须存活，可在自己的回调中使用。
 * @param[in] read_enabled
 *     READ 开关，同值更新也 MOD，不限制直接 accept_batch。
 * @param[out] error
 *     可空独立诊断，全部存储有效/对齐/独立，依赖失败保留完整原因。
 *
 * @retval VIREO_OK
 *     MOD 成功后提交开关，其他绑定保持。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     对象空或依赖拒绝身份。
 * @retval VIREO_RESULT_NOT_FOUND
 *     未绑定或依赖发现失效身份；状态保持。
 * @retval VIREO_RESULT_RANGE
 *     依赖拒绝身份槽范围，合法未损坏绑定不会出现。
 * @retval VIREO_RESULT_IO
 *     MOD 失败，旧开关/绑定保持，不重试。
 *
 * @note 零关注不是注销，ERROR/HANGUP 仍可通知；无自动策略/accept/close。
 *     Reactor-only，无本层分配，保持入口 errno；不得外部更改隐藏注册。
 */
vireo_result_t vireo_acceptor_set_read_enabled(vireo_acceptor_t *acceptor, bool read_enabled,
                                               vireo_acceptor_loop_error_t *error);

/**
 * @brief 单次注销，成功才清本地绑定，不关闭 listener 或结束在途回调
 *
 * @param[in,out] acceptor
 *     非空存活对象，所属 loop 须存活；可 self-detach，未绑定可重复空操作。
 * @param[out] error
 *     可空独立诊断，全部存储有效/对齐/独立，依赖失败保留完整原因。
 *
 * @retval VIREO_OK
 *     无绑定或一次 DEL 成功，绑定/READ 开关清空；当前执行仍须返回。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     对象空或依赖拒绝身份。
 * @retval VIREO_RESULT_NOT_FOUND
 *     依赖身份失效，绑定保持，不吞错误。
 * @retval VIREO_RESULT_RANGE
 *     依赖身份槽范围异常，绑定保持。
 * @retval VIREO_RESULT_IO
 *     DEL 失败，绑定/资源保持，destroy 仍 BUSY，不重试或自动 close。
 *
 * @note self-detach 不解除在途保护：destroy/attach/forget 仍 BUSY，代码/context 活到返回。
 *     Reactor-only，无本层分配，不访问业务 context，保持入口 errno。
 */
vireo_result_t vireo_acceptor_detach(vireo_acceptor_t *acceptor,
                                    vireo_acceptor_loop_error_t *error);

/**
 * @brief 正确所属 loop 已彻底销毁后，只清本地绑定，不访问旧地址
 *
 * @param[in,out] acceptor
 *     非空存活对象，未绑定为空操作；有绑定须满足严格前置。
 * @param[out] error
 *     可空独立诊断，全部存储有效/对齐/独立，成功/拒绝全成员为零。
 *
 * @retval VIREO_OK
 *     本地绑定/READ 开关归空，listener/control 保持。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     对象空。
 * @retval VIREO_RESULT_BUSY
 *     当前业务回调在途，状态保持。
 *
 * @pre 若仍有绑定，调用者已结束正确所属 loop 的全部运行/停止请求者并实际 destroy，
 *     包括 IO 后 owner 已消费；仅 stop/run 返回或 destroy BUSY 不满足。
 *
 * @warning 无法自行验证悬空 loop；在存活 loop 上错误调用会遗留登记，违反调用者前置。
 *
 * @note 不关闭 listener/客户或消费其他对象；Reactor-only，无系统调用，保持入口 errno。
 */
vireo_result_t vireo_acceptor_forget_destroyed_loop(vireo_acceptor_t *acceptor,
                                                   vireo_acceptor_loop_error_t *error);

#endif /* VIREO_NET_ACCEPTOR_H */
