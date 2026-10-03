/*
- PROJECT : VIREO
- FILE    : event_loop.h
- AUTHOR  : bitofux
- DATE    : 2026-10-03
- BRIEF   : 此模块负责：
- -- event loop 资源的唯一所有权与生命周期
- -- 固定就绪工作区、注册表与包含自有 epoll 的统一申请预算
- -- LT 注册绑定、数值身份验证和客户端资源借用
- -- 有限批次分发、持续运行、协作停止与隐藏 pipe 唤醒
 */
#ifndef VIREO_NET_EVENT_LOOP_H
#define VIREO_NET_EVENT_LOOP_H

#include <stddef.h>
#include <stdbool.h>
#include <vireo/net/epoll.h>

/** 固定批次位置数的硬上限，不是注册数量或最大连接数。 */
#define VIREO_EVENT_LOOP_MAX_EVENTS VIREO_EPOLL_MAX_EVENTS

/** 同时有效注册数的硬上限，与批次容量独立。 */
#define VIREO_EVENT_LOOP_MAX_REGISTRATIONS VIREO_EPOLL_MAX_EVENTS

/** 单 loop 的总用户态申请硬上限，含其拥有的 epoll，64 MiB。 */
#define VIREO_EVENT_LOOP_MAX_MEMORY VIREO_EPOLL_MAX_MEMORY

/** 唯一拥有型资源容器；内部 epoll、值数组及布局不公开，不可复制或序列化。 */
typedef struct vireo_event_loop vireo_event_loop_t;

/** 注册的数值身份，零对为空；可复制但不增加所有权，不是认证或持久 ID。 */
typedef struct vireo_event_loop_handle {
    uint64_t loop_id; /**< 所属 loop 的非零身份，销毁后不复用。 */
    uint64_t token;   /**< 本次注册的不透明非零值，不依赖其编码或自行构造。 */
} vireo_event_loop_handle_t;

/**
 * 就绪回调代码在注册期间借用，context 同期存活；若已调用须保持至返回。
 * 参数依次为借用 loop、本次 handle 副本、借用客户端 fd、五个 epoll 项目就绪位、借用 context。
 * 无返回值；回调内部失败由回调或上层处理，不自动使 run/run_once 失败或回滚副作用。
 * 可 ADD/MOD/DEL/观察，包括自注销；当前执行的代码/context 仍须存活至返回。
 * 同 loop 递归 run/run_once 或在途 destroy 返回 BUSY；独立 loop 可嵌套，调用者控制深度和阻塞。
 * 回调须正常返回，不能 longjmp 跳出、强制取消或破坏 loop/独立输出存储。
 */
typedef void (*vireo_event_loop_callback_t)(vireo_event_loop_t *loop,
                                           vireo_event_loop_handle_t handle, int fd,
                                           uint32_t events, void *context);

/** ADD 调用期借用的输入，内容按值保存，fd/代码/context 不转移所有权。 */
typedef struct vireo_event_loop_registration {
    int fd;                                /**< 借用有效描述符，非负，0 合法。 */
    uint32_t interests;                     /**< epoll 三已知项目关注位，允许零。 */
    vireo_event_loop_callback_t callback;   /**< 非 NULL，注册期间固定的借用代码。 */
    void *context;                         /**< 可为 NULL，注册期间固定的借用数据。 */
} vireo_event_loop_registration_t;

/** 创建时调用期借用的选项，无默认值，不保存选项地址。 */
typedef struct vireo_event_loop_options {
    size_t event_capacity;   /**< 固定值数组容量，1..VIREO_EVENT_LOOP_MAX_EVENTS。 */
    size_t max_memory_bytes; /**< 正总申请预算，不超过 VIREO_EVENT_LOOP_MAX_MEMORY。 */
    size_t registration_capacity; /**< 正注册数上限，不超过 MAX_REGISTRATIONS，无默认值。 */
} vireo_event_loop_options_t;

/** 按值数值快照，不授予资源借用，不冻结结构体 ABI。 */
typedef struct vireo_event_loop_info {
    size_t event_capacity;         /**< 固定原生批次上限，内部唤醒也占一项。 */
    size_t events_bytes;           /**< 完整 vireo_epoll_event_t 值数组的申请字节数。 */
    size_t loop_allocation_bytes;  /**< 本层控制块、事件值区与注册区，不包含 epoll。 */
    size_t epoll_allocation_bytes; /**< 由公共 epoll_inspect 得到的自有 epoll 申请数。 */
    size_t allocation_bytes;       /**< 上述两层合计，不是 RSS、内核内存或全局预算。 */
    size_t max_memory_bytes;       /**< 创建时调用者提供的总预算，合计不超过此值。 */
    size_t registration_capacity; /**< 同时有效注册上限，创建后固定。 */
    size_t registrations_bytes;   /**< 完整私有注册记录数组的申请字节，不冻结元素大小。 */
    size_t registered_count;      /**< 当前有效注册数。 */
    size_t available_count;       /**< 空闲槽数，与 registered_count 之和为注册容量。 */
    uint64_t loop_id;              /**< 非零数值身份，不授予资源借用。 */
    bool stop_requested;           /**< 观察时永久停止意图，不保证运行者或请求者已返回。 */
} vireo_event_loop_info_t;

/** 一轮成功后的按值计数，不表示消息、字节、独立连接数或耗时。 */
typedef struct vireo_event_loop_run_info {
    size_t ready_count;      /**< 本轮客户值项数，排除内部唤醒，不超过 event_capacity。 */
    size_t dispatched_count; /**< 实际回调次数，不承诺每个注册最多一次。 */
    size_t stale_count;      /**< 形状合法但当前注册身份已过期的跳过项数。 */
    size_t filtered_count;   /**< 身份有效但按当前关注过滤后无有效位的项数。 */
} vireo_event_loop_run_info_t;

/** 本层进程内诊断阶段，不是 wire 编号或重试策略。 */
typedef enum vireo_event_loop_stage {
    VIREO_EVENT_LOOP_STAGE_NONE = 0,             /**< 成功或本层前置拒绝。 */
    VIREO_EVENT_LOOP_STAGE_ALLOCATE_CONTROL = 1, /**< 本层控制块分配失败。 */
    VIREO_EVENT_LOOP_STAGE_ALLOCATE_EVENTS = 2,  /**< 本层值数组分配失败。 */
    VIREO_EVENT_LOOP_STAGE_CREATE_EPOLL = 3,     /**< epoll 创建拒绝或失败。 */
    VIREO_EVENT_LOOP_STAGE_INSPECT_EPOLL = 4,    /**< 创建后的依赖快照违反公共不变量。 */
    VIREO_EVENT_LOOP_STAGE_DESTROY_EPOLL = 5,    /**< epoll 销毁报错，但 loop 仍已消费。 */
    VIREO_EVENT_LOOP_STAGE_ALLOCATE_REGISTRATIONS = 6, /**< 本层注册表申请失败。 */
    VIREO_EVENT_LOOP_STAGE_ISSUE_ID = 7,         /**< 创建身份耗尽，没有申请资源。 */
    VIREO_EVENT_LOOP_STAGE_ADD = 8,              /**< 底层 ADD 失败。 */
    VIREO_EVENT_LOOP_STAGE_MOD = 9,              /**< 底层 MOD 失败。 */
    VIREO_EVENT_LOOP_STAGE_DEL = 10,             /**< 底层 DEL 失败。 */
    VIREO_EVENT_LOOP_STAGE_WAIT = 11,            /**< 等待失败或批次数量/就绪位异常。 */
    VIREO_EVENT_LOOP_STAGE_DISPATCH = 12,        /**< 客户批次 token 形状异常。 */
    VIREO_EVENT_LOOP_STAGE_WAKE_CREATE = 13,     /**< 创建内部 pipe 失败。 */
    VIREO_EVENT_LOOP_STAGE_WAKE_REGISTER = 14,   /**< 注册内部读端失败。 */
    VIREO_EVENT_LOOP_STAGE_WAKE_READ = 15,       /**< 读取提示失败或控制事件异常。 */
    VIREO_EVENT_LOOP_STAGE_STOP_NOTIFY = 16,     /**< 意图已提交，但通知失败或进度异常。 */
    VIREO_EVENT_LOOP_STAGE_CLOSE_WRITE = 17,     /**< 写端关闭报错，资源仍消费。 */
    VIREO_EVENT_LOOP_STAGE_CLOSE_READ = 18       /**< 读端关闭报错，资源仍消费。 */
} vireo_event_loop_stage_t;

/** 调用者持有的独立诊断；成功时两层阶段均为 NONE，system_errno 为零。 */
typedef struct vireo_event_loop_error {
    vireo_event_loop_stage_t stage; /**< 本层检测到的失败阶段。 */
    vireo_epoll_error_t epoll_error; /**< 依赖原诊断；本层错误为 NONE/0，旧观察回滚可记关闭错误。 */
    int system_errno;               /**< 本层 pipe/read/write/close 原因；成功及不变量异常为零。 */
} vireo_event_loop_error_t;

/**
 * @brief 创建固定工作区、注册表、自有 epoll 与停止通知 pipe，完整成功后发布唯一 owner
 *
 * @param[in] options
 *     非 NULL、存活且调用期间稳定的选项，仅借用到返回。
 * @param[in,out] out_loop
 *     非 NULL、正确对齐的可写 owner 存储，入口值必须为 NULL；成功接管对象，
 *     最终须用 vireo_event_loop_destroy 释放。
 * @param[out] out_error
 *     可为 NULL，否则为独立可写诊断，每次覆盖全部成员。
 *
 * @retval VIREO_OK
 *     取得全部资源并发布对象；尚未建立客户注册、等待或分发；内部读端已注册。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需指针 NULL、owner 非空或选项数值为零。
 * @retval VIREO_RESULT_OVERFLOW
 *     本层数组乘加不可由 size_t 表示，或不复用的 loop 身份已耗尽。
 * @retval VIREO_RESULT_RANGE
 *     容量/预算超过硬限，或本层及自有 epoll 需求超过总预算。
 * @retval VIREO_RESULT_NO_MEMORY
 *     本层或自有 epoll 的用户态分配失败；两层阶段定位分配点。
 * @retval VIREO_RESULT_IO
 *     epoll 创建/内部读端 ADD 或 pipe 创建失败，两类诊断分别保存原 errno。
 * @retval VIREO_RESULT_INTERNAL
 *     依赖快照违反公开容量/预算不变量；已回滚，关闭错误留在嵌套诊断。
 *
 * @note 顺序：参数→本层受检乘加→硬限/预算→取得身份→本层三点分配→剩余预算交 epoll_create
 *     →公共 inspect 核对实际合计→pipe2→内部读端 ADD→发布。失败保持 owner，逆序释放已取得资源。
 *     不缩小容量或自动重试；回滚错误不覆盖主要结果与本层阶段。
 * @note 所有权：对象独占 epoll、固定值数组、注册表和内部 pipe 两端，
 *     不公开 fd、epoll 句柄或工作区借用。
 *     值数组未填充，不授予事件读取权；本接口不接管客户端 fd。
 * @note 预算：包含本层控制块/值数组/注册表及自有 epoll 控制块/原生数组。后者仅通过公共合同计入，
 *     不依赖其私有 sizeof；不含分配器开销、页/RSS、内核 pipe/watch、连接或多 loop 全局资源。
 * @note 输入、owner、诊断与自有资源互不重叠；地址必须真实有效，NULL 检查不验证坏地址。
 * @note 线程安全：reactor-only，无内部锁；启动装配可在交接前创建，owner 输出须独占。
 *     不支持 signal handler、执行中强制取消或 fork 后未 exec 复用对象。
 * @note errno：所有路径恢复调用前值；诊断可空，不改变处理。
 *     依赖原因从 epoll_error、本层系统原因从 system_errno 读取。
 * @note 身份在本库实例范围用原子发放，失败创建可消耗且不复用；不用于跨进程或安全认证。
 *     原子仅保证身份唯一，不发布对象；本层可变注册仍归 Reactor，
 *     停止请求以独立原子和隐藏 pipe 同步。
 */
vireo_result_t vireo_event_loop_create(vireo_event_loop_options_t const *options,
                                      vireo_event_loop_t **out_loop,
                                      vireo_event_loop_error_t *out_error);

/**
 * @brief 按值读取两层容量与用户态申请数，不暴露资源
 *
 * @param[in] loop
 *     非 NULL、存活对象，仅调用期间借用，所有权保持。
 * @param[out] out_info
 *     非 NULL、正确对齐且可写的独立输出，不与自有资源重叠。
 *
 * @retval VIREO_OK
 *     完整提交资源、当前注册计数与原子停止意图快照，不改变对象。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     任一参数 NULL，输出全部字节保持。
 *
 * @note 副本不延长对象生命期，不冻结私有布局，注册计数不表示已有就绪事件。
 * @note 线程安全：reactor-only；仅 request_stop 可并发，其他访问及销毁须协调。
 * @note errno：不读取、不保存且不修改；无分配或系统调用。
 */
vireo_result_t vireo_event_loop_inspect(vireo_event_loop_t const *loop,
                                       vireo_event_loop_info_t *out_info);

/**
 * @brief 销毁自有 epoll 与本层工作区，消费并清空唯一 owner
 *
 * @param[in,out] loop
 *     非 NULL、正确对齐且可写的 owner 存储；*loop 可为 NULL，非空须为存活唯一对象，
 *     owner 存储不能位于将释放的资源内。
 * @param[out] out_error
 *     可为 NULL，否则为独立可写诊断，不与 owner/自有资源重叠。
 *
 * @retval VIREO_OK
 *     全部资源已释放，owner 为 NULL；入口为空 owner 时是成功空操作。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     owner 地址为 NULL。
 * @retval VIREO_RESULT_BUSY
 *     对象正在 run 或 run_once，owner 及全部资源保持；须等整个运行返回。
 * @retval VIREO_RESULT_IO
 *     自有 epoll 或内部 pipe 关闭报错；首错保留，仍消费全部 loop 资源。
 *
 * @note epoll_destroy→写端 close→读端 close 各一次；IO 也继续释放三个 heap 块并清空 owner。
 *     全部旧别名失效。
 *     不重试旧句柄；允许活跃注册，全部 handle 及注册借用终止，不逐项 DEL/调用回调，
 *     不关闭客户端或释放 context，不完成服务器停机；空 owner 可重复 destroy。
 * @note 线程安全：reactor-only，须等运行者及全部停止请求者结束借用后销毁，禁止并发销毁或取消。
 *     在途标记只防同线程重入，不能从其他线程尝试 destroy 来查询是否正在运行。
 * @note errno：所有路径恢复入口值；NULL 诊断不改变清理策略。
 */
vireo_result_t vireo_event_loop_destroy(vireo_event_loop_t **loop,
                                       vireo_event_loop_error_t *out_error);


/**
 * @brief 建立固定回调绑定，内核 ADD 成功后发布新数值身份
 *
 * @param[in,out] loop
 *     非 NULL 存活对象，调用期借用；注册变更仅属 Reactor。
 * @param[in] registration
 *     非 NULL、调用期稳定的独立输入；fd 非负、callback 非 NULL、context 可空；
 *     interests 只含 epoll 三已知关注位，可为零。fd/代码/context 借用至成功 DEL 或销毁。
 * @param[in,out] out_handle
 *     非 NULL 独立可写输出，入口两成员必须为零；成功取得身份，不接管客户端资源。
 * @param[out] out_error
 *     可空独立诊断，每次覆盖全部成员。
 *
 * @retval VIREO_OK
 *     保存完整绑定并发布新 handle，没有执行回调。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL、负 fd、未知关注位、空 callback 或非空输出。
 * @retval VIREO_RESULT_BUSY
 *     同一 fd 数值已注册或固定注册表满；不调用内核。
 * @retval VIREO_RESULT_OVERFLOW
 *     注册发放序号已耗尽，不回绕；已有注册仍可 MOD/DEL。
 * @retval VIREO_RESULT_IO
 *     严格一次底层 ADD 失败，ADD 阶段/嵌套原 errno，无自动重试。
 *
 * @note 失败保持 handle、活跃绑定与空闲槽；系统 ADD 失败可消耗发放序号，不回退。
 *     同 fd 检测扫描有界表，身份查找直接索引，不承诺 ADD 为常数时间或硬实时。
 * @note callback/context 在注册期间固定；更换绑定需 DEL 再 ADD，两步不是原子事务。
 *     输入地址不保留；不分配用户态内存，不 dup/close 客户端，不改变其阻塞/CLOEXEC 属性。
 * @note 零关注不是注销，仍可能 ERROR/HANGUP。客户端 fd 不得未经成功注销就关闭/复用；
 *     数值身份不能检测任意外部 close/reuse，也不是安全认证。
 * @note 线程安全：reactor-only，无内部锁，禁止并发 fd 操作/销毁、signal handler 或强制取消。
 * @note errno：全部路径保持入口值，可空诊断不改变策略，输入/输出/资源互不重叠。
 */
vireo_result_t vireo_event_loop_add(vireo_event_loop_t *loop,
                                    vireo_event_loop_registration_t const *registration,
                                    vireo_event_loop_handle_t *out_handle,
                                    vireo_event_loop_error_t *out_error);

/**
 * @brief 完整替换有效注册的关注位，固定绑定和身份保持
 *
 * @param[in,out] loop
 *     非 NULL 存活对象，调用期借用。
 * @param[in] handle
 *     注册身份副本，不增加所有权；仅所属 loop 当前活跃身份有效。
 * @param[in] interests
 *     epoll 三已知项目关注位，可为零；全替换而非合并。
 * @param[out] out_error
 *     可空独立诊断，每次覆盖全部成员。
 *
 * @retval VIREO_OK
 *     严格一次 MOD 成功，新关注已保存，fd/callback/context/handle 保持。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     loop NULL、未知位、畸形或跨 loop 身份。
 * @retval VIREO_RESULT_NOT_FOUND
 *     全零空身份或已过期/注销身份。
 * @retval VIREO_RESULT_RANGE
 *     身份的槽位置超出本 loop 注册容量。
 * @retval VIREO_RESULT_IO
 *     底层 MOD 失败，旧绑定与关注保持，MOD/嵌套原 errno，无 fallback/retry。
 *
 * @note reactor-only；客户端和上下文须继续存活，身份副本不撤回已复制事件。
 *     不分配、收发、关闭或执行回调；输入/诊断/资源独立，保持入口 errno。
 */
vireo_result_t vireo_event_loop_mod(vireo_event_loop_t *loop, vireo_event_loop_handle_t handle,
                                    uint32_t interests, vireo_event_loop_error_t *out_error);

/**
 * @brief 注销有效绑定，内核 DEL 成功后释放槽位并清空身份
 *
 * @param[in,out] loop
 *     非 NULL 存活对象，调用期借用。
 * @param[in,out] handle
 *     非 NULL 独立可写身份，成功清空，其他副本随后也不再有效。
 * @param[out] out_error
 *     可空独立诊断，每次覆盖全部成员。
 *
 * @retval VIREO_OK
 *     一次 DEL 成功，槽位可复用，注册借用结束；已在执行的回调须先安全返回。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL、畸形或跨 loop 身份。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空身份、已注销或过期身份；空 DEL 不是成功空操作。
 * @retval VIREO_RESULT_RANGE
 *     槽位置超出容量。
 * @retval VIREO_RESULT_IO
 *     底层 DEL 失败，handle/记录及借用保持，DEL/嵌套原 errno，不吞 ENOENT 或重试。
 *
 * @note 不 close 客户端或 free context。成功后上层再关闭 fd/释放资源；失败先协调恢复，
 *     不能提前释放借用。可先停止所有使用，再整体 destroy 结束全部注册。
 * @note reactor-only，无内部锁；输出/诊断/资源独立，无分配，保持入口 errno。
 *     DEL 不修改旧事件值副本，后续分发必须重新校验身份。
 */
vireo_result_t vireo_event_loop_del(vireo_event_loop_t *loop, vireo_event_loop_handle_t *handle,
                                    vireo_event_loop_error_t *out_error);

/**
 * @brief 按值观察一次当前有效注册，不转移或延长资源借用
 *
 * @param[in] loop
 *     非 NULL 存活对象，调用期借用。
 * @param[in] handle
 *     当前身份副本，借用所指注册须有效。
 * @param[out] out_registration
 *     非 NULL 独立可写输出，成功复制全部绑定；context/代码/fd 仍由原 owner 持有。
 *
 * @retval VIREO_OK
 *     复制 fd/关注/回调/context，不改变对象。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL、畸形或跨 loop 身份。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空身份或已过期/注销。
 * @retval VIREO_RESULT_RANGE
 *     槽位置超出容量。
 *
 * @note 全部失败保持整个输出；成功副本不延长注册、代码或 context 的生命期。
 *     reactor-only，无分配/系统调用，不读写 errno，输出与输入/资源互不重叠。
 */
vireo_result_t vireo_event_loop_registration_inspect(
    vireo_event_loop_t const *loop, vireo_event_loop_handle_t handle,
    vireo_event_loop_registration_t *out_registration);

/**
 * @brief 等待一次并按当前有效身份及关注分发有限批次，成功后提交本轮计数
 *
 * @param[in,out] loop
 *     非 NULL 存活对象，Reactor 独占运行与登记至返回，允许合法并发停止请求。
 *     内部工作区不对外借出。
 * @param[in] timeout_ms
 *     -1 无限等待、0 立即返回、正值相对毫秒；小于 -1 非法，不包含回调执行时间。
 * @param[out] out_info
 *     非 NULL、正确对齐且独立可写的本轮输出，失败保持全部字节。
 * @param[out] out_error
 *     可空独立可写诊断，每次覆盖全部成员。
 *
 * @retval VIREO_OK
 *     完整分发本批客户项，后三计数之和等于 ready_count；无客户项或入口已停止为四零。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需指针 NULL 或 timeout_ms 小于 -1。
 * @retval VIREO_RESULT_BUSY
 *     同一 loop 已在 run 或 run_once 内，未等待、分发或改变外层工作区。
 * @retval VIREO_RESULT_IO
 *     等待或内部提示读取失败，分别保留依赖/本层原 errno，包括 EINTR；不自动重试。
 * @retval VIREO_RESULT_INTERNAL
 *     依赖异常批次，或数量/已知就绪位/token 形状违反本层不变量；零回调。
 *
 * @note 顺序：参数→在途检查→停止检查→一次公共 epoll_wait→全批检查→提示读取→客户分发。
 *     等待、预检查或提示读取失败均无本轮回调，统计保持；内层工作区可改变，所有受控返回清在途标记。
 *     自行检测异常的系统原因均为零；依赖失败保留其完整诊断。
 * @note 过期 token 计 stale；有效身份按当前关注过滤 READ/WRITE/PEER_WRITE_CLOSED，
 *     ERROR/HANGUP 始终保留；无有效位计 filtered。按返回顺序处理，不排序或去重。
 *     逐项取当前绑定的值副本，回调后不访问其记录/context；不预取整批借用指针。
 * @note 回调可修改注册，后续项读取修改后的当前状态；新注册不继承旧 token 事件。
 *     自注销不能提前释放仍在执行的代码/context。回调内部错误由回调/上层处理，
 *     无自动关闭客户端、销毁全部注册或业务副作用回滚。
 * @note 本层无运行期申请或收发；最多处理 event_capacity 个值项，不限制回调字节/耗时。
 *     回调须自行保持有界非阻塞；LT 后续轮处理仍就绪对象，不承诺时间公平或内核返回顺序。
 * @note 内部 token 0 仅 READ 提示，不分发、不计客户四计数，但占原生批次容量。
 *     控制提示一次最多读 64 字节，EAGAIN 为过期提示；异常控制项/EOF 为 INTERNAL。
 *     入口已停止时不等待而成功四零；取得批次后仍完整处理，不抢占回调。
 *     -1 可阻塞到客户就绪或合法停止通知；调用者安排下一轮与错误恢复。
 *     禁止同 loop 在途销毁/递归运行；独立 loop 可嵌套，由调用者控制深度和等待时间。
 * @note 线程安全：reactor-only，无运行锁；仅 request_stop 可跨线程并发，其他访问仍禁止。
 *     输入/输出/自有资源互不重叠，输出整个调用期间独占存活，回调不能改写或释放它们。
 *     不支持 signal handler、强制取消、longjmp 跳出或 fork 后未 exec 复用。
 * @note errno：所有路径恢复入口值，包括回调改变 errno；诊断可空，不改变处理策略。
 */
vireo_result_t vireo_event_loop_run_once(vireo_event_loop_t *loop, int timeout_ms,
                                        vireo_event_loop_run_info_t *out_info,
                                        vireo_event_loop_error_t *out_error);


/**
 * @brief 持续等待和分发，观察到永久停止意图后成功返回
 *
 * @param[in,out] loop
 *     非 NULL 存活对象，Reactor 借用至返回；仅停止请求可合法跨线程并发。
 * @param[out] out_error
 *     可空独立可写诊断，调用期间独占，不能与资源/其他调用输出重叠。
 *
 * @retval VIREO_OK
 *     已观察停止；入口已停止则不等待，重复调用仍成功，不复位状态。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     loop 为 NULL。
 * @retval VIREO_RESULT_BUSY
 *     同 loop 已在 run/run_once 中，不等待、不改变外层工作区。
 * @retval VIREO_RESULT_IO
 *     某轮等待或控制读失败，保留原始阶段/errno，不自动重试 EINTR。
 * @retval VIREO_RESULT_INTERNAL
 *     某轮批次或内部控制进度异常。
 *
 * @note 每轮 timeout 为 -1，复用固定工作区；没有运行期 heap 或累计统计，不引入时钟/deadline。
 *     run_active 覆盖整个调用。错误清标记并返回；此前轮的回调副作用不回滚，
 *     不承诺全程失败零回调。等待错误优先返回，不因并发 stop 隐藏失败。
 * @note 停止只在下一轮开始前生效，已经取得的客户批次完整处理；回调须有界非阻塞。
 *     返回不自动 DEL/close 客户端、flush buffer 或结束其他请求者；新运行需新建 loop。
 * @note reactor-only；允许回调注册变更/观察/request_stop，禁止同 loop 再运行/销毁，
 *     独立 loop 可嵌套，代码/context 借用和正常返回前置沿用 run_once。
 * @note 全部路径恢复入口 errno，包括回调修改；诊断可空不改变处理。
 */
vireo_result_t vireo_event_loop_run(vireo_event_loop_t *loop,
                                   vireo_event_loop_error_t *out_error);

/**
 * @brief 原子提交永久停止意图，并尝试一次非阻塞通知解除等待
 *
 * @param[in,out] loop
 *     非 NULL 存活对象，仅借用；地址须经外部同步发布并保持到全部调用者结束。
 * @param[out] out_error
 *     可空独立可写诊断，各并发调用须独占不同输出，不能与资源重叠。
 *
 * @retval VIREO_OK
 *     意图已提交，通知写入或 EAGAIN/EWOULDBLOCK 表示已有提示；不保证运行已返回。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     loop 为 NULL。
 * @retval VIREO_RESULT_IO
 *     意图已提交，但单次通知失败，STOP_NOTIFY/system_errno 保存含 EINTR 的原原因。
 * @retval VIREO_RESULT_INTERNAL
 *     意图已提交，但通知返回零或异常进度，STOP_NOTIFY/system_errno 为零。
 *
 * @note thread-safe，可多请求者并发或从回调调用；只访问停止原子及发布后不变的写端/ops。
 *     不访问 run_active/注册表，不授权其他线程 inspect、登记、fd 操作或销毁。
 * @note 先提交 true，再写一字节；重复调用也尝试通知，IO/INTERNAL 不撤回意图，
 *     若运行者仍阻塞，调用者可再次请求补通知。无自动重试、复位或回调抢占，不等待 join。
 * @note loop 独占并隐藏 pipe 两端，所有请求者结束后才允许关闭，合法借用保证读端仍活。
 *     销毁须先等运行者及全部请求者结束；原子标记不保护悬空指针或并发 destroy。
 * @note 无 heap；每次一次 write，非阻塞不等于无调度延迟或 lock-free 原子保证。
 *     不支持 signal handler、强制取消或 fork 后未 exec 复用；全部路径保持入口 errno。
 */
vireo_result_t vireo_event_loop_request_stop(vireo_event_loop_t *loop,
                                            vireo_event_loop_error_t *out_error);

#endif /* VIREO_NET_EVENT_LOOP_H */
