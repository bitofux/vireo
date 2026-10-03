/*
- PROJECT : VIREO
- FILE    : connection_pool.h
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 固定容量连接管理容器的空态构造、数值观测与销毁
- -- 显式容器申请预算、失败保持与唯一所有权
- -- 已有连接收纳、存储租约查找与安全归还
 */
#ifndef VIREO_NET_CONNECTION_POOL_H
#define VIREO_NET_CONNECTION_POOL_H

#include <stddef.h>
#include <stdint.h>
#include <vireo/base/result.h>
#include <vireo/net/connection.h>

/** 固定管理槽数量硬上限；不是连接字节数或文件描述符上限。 */
#define VIREO_CONNECTION_POOL_MAX_CAPACITY ((size_t)65536)
/** 单容器总申请硬上限，64 MiB；不包含连接及其间接资源。 */
#define VIREO_CONNECTION_POOL_MAX_MEMORY ((size_t)67108864)
/** 全池拥有连接的固定双 buffer 容量硬上限；不含容器申请或池外对象。 */
#define VIREO_CONNECTION_POOL_MAX_BUFFER_MEMORY ((size_t)67108864)

/** 唯一拥有型容器，布局不公开；全部入口 Reactor-only。 */
typedef struct vireo_connection_pool vireo_connection_pool_t;

/** 按值读取，无默认值，不保存调用者地址。 */
typedef struct vireo_connection_pool_options {
    size_t capacity;         /**< 1..MAX_CAPACITY 个固定管理槽。 */
    size_t max_memory_bytes; /**< 1..MAX_MEMORY 字节显式总申请预算。 */
    size_t max_buffer_bytes; /**< 1..MAX_BUFFER_MEMORY 字节独立双 buffer 总容量额度。 */
} vireo_connection_pool_options_t;

/** 按值数值快照，不包含连接、槽位、基础池或 fd 的借用。 */
typedef struct vireo_connection_pool_info {
    size_t capacity;                   /**< 固定管理槽数量。 */
    size_t leased_slots;               /**< 基础池在用槽数，等于池拥有的连接数量。 */
    size_t available_slots;            /**< capacity - leased_slots。 */
    size_t index_bytes;                /**< 独立固定索引申请字节。 */
    size_t container_allocation_bytes; /**< 本层控制块与索引合计。 */
    size_t storage_allocation_bytes;   /**< 基础池公开报告的完整申请。 */
    size_t allocation_bytes;           /**< 上述两层合计，不超过显式预算。 */
    size_t max_memory_bytes;           /**< 创建时给出的预算。 */
    size_t buffer_capacity_bytes;      /**< 当前拥有连接的固定读写区容量合计，含空余字节。 */
    size_t max_buffer_bytes;           /**< 创建时给出的全池双 buffer 容量额度。 */
} vireo_connection_pool_info_t;

/** 本层失败阶段，不替换依赖结果分类；没有系统调用 errno 诊断。 */
typedef enum vireo_connection_pool_stage {
    VIREO_CONNECTION_POOL_STAGE_NONE = 0,             /**< 成功或尚未调用资源依赖。 */
    VIREO_CONNECTION_POOL_STAGE_CREATE_STORAGE = 1,   /**< 基础池公开构造失败。 */
    VIREO_CONNECTION_POOL_STAGE_INSPECT_STORAGE = 2,  /**< 基础池观测失败或快照异常。 */
    VIREO_CONNECTION_POOL_STAGE_ALLOCATE_CONTROL = 3, /**< 本层控制块申请失败。 */
    VIREO_CONNECTION_POOL_STAGE_ALLOCATE_INDEX = 4,   /**< 本层索引申请失败。 */
    VIREO_CONNECTION_POOL_STAGE_DESTROY_STORAGE = 5   /**< 基础池拒绝销毁。 */
} vireo_connection_pool_stage_t;

/** 不拥有资源的按值阶段诊断；错误类别由函数结果码提供。 */
typedef struct vireo_connection_pool_error {
    vireo_connection_pool_stage_t stage; /**< 成功和参数拒绝时为 NONE。 */
} vireo_connection_pool_error_t;

/**
 * 按值存储租约，全零为无租约；不拥有资源，不冻结 ABI 或提供认证。
 * 复制不增加权限，归还任一副本使全部副本失效；不是阶段 7 的异步连接身份。
 */
typedef struct vireo_connection_pool_lease {
    uint64_t pool_id;    /**< 基础存储的非零进程内身份，不复用、非持久标识。 */
    size_t slot_index;   /**< 小于 capacity 的管理槽号，不是 fd 或字节偏移。 */
    uint64_t generation; /**< 基础存储本次非零发放序号，不回绕。 */
} vireo_connection_pool_lease_t;

/** 独立收纳/归还诊断阶段，不改变资源构造的阶段枚举。 */
typedef enum vireo_connection_pool_operation_stage {
    VIREO_CONNECTION_POOL_OPERATION_NONE = 0,               /**< 成功或先验拒绝。 */
    VIREO_CONNECTION_POOL_OPERATION_INSPECT_CONNECTION = 1, /**< 公开连接快照失败或异常。 */
    VIREO_CONNECTION_POOL_OPERATION_ACQUIRE_SLOT = 2,       /**< 基础槽领取失败或异常。 */
    VIREO_CONNECTION_POOL_OPERATION_DESTROY_CONNECTION = 3, /**< 连接拒绝或消费型关闭 IO。 */
    VIREO_CONNECTION_POOL_OPERATION_RELEASE_SLOT = 4        /**< 合法基础租约归还不变量异常。 */
} vireo_connection_pool_operation_stage_t;

/** 按值操作诊断；只有连接销毁失败时保留原 connection 诊断。 */
typedef struct vireo_connection_pool_operation_error {
    vireo_connection_pool_operation_stage_t stage; /**< 此次本层操作阶段。 */
    vireo_connection_error_t connection_error;     /**< 原连接错误，其他阶段为 NONE/0。 */
} vireo_connection_pool_operation_error_t;

/**
 * @brief 在显式总预算内创建完整空容器，然后发布唯一 owner
 *
 * @param[in] options
 *     非空有效选项，只在调用期间借用。
 * @param[in,out] out_pool
 *     非空独立拥有者地址，入口必须为 NULL；成功后最终交给 destroy。
 * @param[out] error
 *     可空独立诊断，非空时每次覆盖阶段。
 *
 * @retval VIREO_OK
 *     基础池、控制块与固定索引初始化完毕，发布空容器。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空、入口 owner 非空或任一选项为零。
 * @retval VIREO_RESULT_OVERFLOW
 *     本层受检乘加不可表示，或基础池公开构造返回 OVERFLOW。
 * @retval VIREO_RESULT_RANGE
 *     超过硬限、本层开销未留下正预算，或基础池需求超过剩余预算。
 * @retval VIREO_RESULT_NO_MEMORY
 *     任一申请失败；逆序释放已获资源。
 * @retval VIREO_RESULT_INTERNAL
 *     基础池成功快照与其公开合同不一致。
 *
 * @note 顺序：参数→本层受检算术→硬限/正剩余→公开基础池 create/inspect→本层申请→发布。
 *     依赖失败保留原结果分类；所有失败保持 owner，诊断只指出本层调用阶段。
 * @note 预算含本层控制块、索引及基础池完整申请；不含连接/双 buffer、内核、分配器开销、
 *     RSS 或全局多池预算；不保证申请成功或性能。创建空池不接管 fd 或 connection。
 * @note max_buffer_bytes 是后续收纳连接的双固定字节区容量额度，必须显式为正，不分配这些区；
 *     旧两字段选项初始化需补此字段，不提供隐式默认。两预算独立且各自受硬限约束。
 * @note 输入、owner、诊断为存活正确对齐的独立存储，不相互重叠或位于自有资源内。
 *     复制句柄不复制所有权，全部操作由所属 Reactor 串行执行。
 * @note 所有路径保持入口 errno，不重试；不支持 signal handler、异步取消或 fork 后 exec 前操作。
 */
vireo_result_t vireo_connection_pool_create(vireo_connection_pool_options_t const *options,
                                           vireo_connection_pool_t **out_pool,
                                           vireo_connection_pool_error_t *error);

/**
 * @brief 按值读取容器计数及完整申请字节，不授予槽位访问权
 *
 * @param[in] pool
 *     非空存活容器，仅调用期间借用。
 * @param[out] out_info
 *     非空独立可写快照，失败保持全部字节。
 *
 * @retval VIREO_OK
 *     基础池快照核对通过后提交完整数值结果。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空；依赖失败也原样保留结果分类。
 * @retval VIREO_RESULT_INTERNAL
 *     基础池快照违反固定布局、身份或计数不变量。
 *
 * @note Reactor-only；不申请、不收纳连接，数值副本不延长容器生命期；保持入口 errno。
 */
vireo_result_t vireo_connection_pool_inspect(vireo_connection_pool_t const *pool,
                                            vireo_connection_pool_info_t *out_info);

/**
 * @brief 销毁空容器；非空拒绝，基础池成功释放后才消费本层 owner
 *
 * @param[in,out] pool
 *     非空独立唯一拥有者地址；*pool 可为 NULL，句柄别名不能提供第二份所有权。
 * @param[out] error
 *     可空独立阶段诊断。
 *
 * @retval VIREO_OK
 *     已释放全部容器资源并置 NULL，或空 owner 成功空操作。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     拥有者地址为空。
 * @retval VIREO_RESULT_BUSY
 *     仍拥有连接或基础池仍有租约，保持 owner、所有资源；其他依赖失败分类原样返回。
 *
 * @note 不批量销毁连接；调用者先结束使用并逐一 release，空容器销毁不关闭客户 fd。
 *     成功使旧别名失效；先结束全部同容器操作。Reactor-only，所有路径保持入口 errno。
 */
vireo_result_t vireo_connection_pool_destroy(vireo_connection_pool_t **pool,
                                            vireo_connection_pool_error_t *error);

/**
 * @brief 接管已有唯一连接 owner，成功才发布存储租约
 *
 * @param[in,out] pool
 *     非空存活容器，由所属 Reactor 串行操作。
 * @param[in,out] connection_owner
 *     非空独立唯一 owner 地址，入口对象非空、未绑定、非回调在途且 OPEN；成功置 NULL。
 * @param[out] out_lease
 *     非空独立租约输出，成功覆盖；不得因此丢失尚未归还的唯一记录。
 * @param[out] error
 *     可空独立操作诊断，每次覆盖。
 *
 * @retval VIREO_OK
 *     池取得连接所有权，槽/索引/计数/容量账与租约同时发布。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址或输入对象为空；依赖失败分类原样返回。
 * @retval VIREO_RESULT_RANGE
 *     单连接双 buffer 容量超过全池额度。
 * @retval VIREO_RESULT_BUSY
 *     连接已绑定、回调在途、正在关闭，或槽位/累计 buffer 额度暂不足。
 * @retval VIREO_RESULT_OVERFLOW
 *     受检容量合计不可表示，或基础存储发放序号耗尽。
 * @retval VIREO_RESULT_INTERNAL
 *     公开快照或基础槽输出违反合同不变量。
 *
 * @note 失败保持输入 owner、全部租约输出及连接字节；无运行期分配，不直接接管 fd，
 *     不改变 EOF/排队数据、fd 属性或 loop 登记。只验证公开容量，不猜测 connection 布局。
 * @note 先验连接/预算检查后才领取基础槽，不承诺跨层拒绝优先级。池外临时对象不计此额度。
 * @note owner/租约/诊断为存活、正确对齐、互不重叠的独立存储，不在池或连接自有资源内。
 *     旧 owner 别名不得再当 owner 使用；字节 view 仍服从 connection 原期限。
 * @note Reactor-only，所有路径保持入口 errno；无异步身份、自动收发或损坏对象修复保证。
 */
vireo_result_t vireo_connection_pool_adopt(vireo_connection_pool_t *pool,
                                          vireo_connection_t **connection_owner,
                                          vireo_connection_pool_lease_t *out_lease,
                                          vireo_connection_pool_operation_error_t *error);

/**
 * @brief 按当前存储租约取得短期连接借用
 *
 * @param[in] pool
 *     非空存活容器，所属 Reactor 调用期间借用。
 * @param[in] lease
 *     按值数值租约，不延长池或连接的生命期。
 * @param[out] out_connection
 *     非空、正确对齐的独立指针输出；成功获得可用 public API 的 borrowed 连接。
 *
 * @retval VIREO_OK
 *     提交当前连接借用，不改变状态或所有权。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空、非空租约身份/代际为零或属于其他池。
 * @retval VIREO_RESULT_RANGE
 *     同池槽号超出固定容量。
 * @retval VIREO_RESULT_NOT_FOUND
 *     全零、槽已空闲或代际过期。
 * @retval VIREO_RESULT_INTERNAL
 *     当前索引与连接 owner 不变量异常。
 *
 * @note 失败保持输出所有字节。借用不得 destroy、当 owner 再 adopt、释放或交给 worker；
 *     结束于该连接 release 的消费（含 IO），复制指针不延长期限。其他槽操作不结束此借用。
 * @note byte/frame view 仍受 connection 原期限约束，调用者必须在归还前结束全部借用。
 *     输出不得位于池/连接资源内；Reactor-only，保持入口 errno，无分配或系统调用。
 */
vireo_result_t vireo_connection_pool_lookup(vireo_connection_pool_t const *pool,
                                           vireo_connection_pool_lease_t lease,
                                           vireo_connection_t **out_connection);

/**
 * @brief 销毁当前租约对应的连接并归还管理槽及容量额度
 *
 * @param[in,out] pool
 *     非空存活容器，所属 Reactor 独占调用。
 * @param[in,out] lease
 *     非空、正确对齐的独立数值存储，不在自有资源内；成功消费后清三个字段。
 * @param[out] error
 *     可空独立操作诊断；消费型 IO 保留完整原 connection 错误。
 *
 * @retval VIREO_OK
 *     连接已销毁、槽/额度已归还、租约清零。
 * @retval VIREO_RESULT_IO
 *     单次 close 失败；仍已消费连接并归还槽/额度、清零租约，不重试旧 fd。
 * @retval VIREO_RESULT_BUSY
 *     连接仍绑定或回调在途，保持租约/owner/资源/额度。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空、非空租约身份/代际为零或跨池。
 * @retval VIREO_RESULT_RANGE
 *     同池槽号超出容量。
 * @retval VIREO_RESULT_NOT_FOUND
 *     全零、已归还或过期租约。
 * @retval VIREO_RESULT_INTERNAL
 *     依赖或本层不变量异常；损坏对象/违约 hook 不提供恢复保证。
 *
 * @note 不自动 DEL；先成功 detach、回调返回且结束全部其他使用/借用。任意关闭阶段均可归还，
 *     可以放弃未发数据。READY、self-detach 成功都不能代替回调已返回的前置。
 * @note 先验证数值再访问索引，OK/IO 结束全部旧别名/借用，其他副本随后 NOT_FOUND。
 *     先销毁间接资源再通过独立局部基础租约归还，不再读取已归还槽字节。
 * @note 参数/数值拒绝保持租约，成功只清字段不承诺 padding；Reactor-only，保持入口 errno。
 */
vireo_result_t vireo_connection_pool_release(vireo_connection_pool_t *pool,
                                            vireo_connection_pool_lease_t *lease,
                                            vireo_connection_pool_operation_error_t *error);

#endif /* VIREO_NET_CONNECTION_POOL_H */
