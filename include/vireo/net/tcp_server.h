/*
- PROJECT : VIREO
- FILE    : tcp_server.h
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 空 server 对独占 loop 与连接池的资源装配
- -- 受检容器预算、按值观察、失败清理与唯一所有权
- -- 已有监听 owner 的收纳、单 loop 绑定与整体资源清理
- -- 有界客户准入、固定元数据与显式逐客户释放
- -- 按当前租约的字节收发、只读借用与前缀消费
- -- 有界完整帧查看与原协议原因转送
- -- 同步 handler、独立响应编码与排队后消费
- -- 有界轮次的持续运行、逐轮结果交付与永久停止透传
- -- 停止后的有限槽扫描、客户清理与消费事实报告
 */
#ifndef VIREO_NET_TCP_SERVER_H
#define VIREO_NET_TCP_SERVER_H

#include <vireo/net/acceptor.h>
#include <vireo/net/connection_pool.h>
#include <vireo/net/event_loop.h>

/** 为 listener 留一个客户注册槽；不是每批就绪数量。 */
#define VIREO_TCP_SERVER_MAX_CONNECTIONS ((size_t)65535)
/** 本层及其拥有容器的用户态申请硬限，不是 RSS 或客户 buffer 总额。 */
#define VIREO_TCP_SERVER_MAX_MEMORY ((size_t)67108864)

/** 唯一拥有型资源根，布局隐藏；除request_stop外全部入口Reactor-only。 */
typedef struct vireo_tcp_server vireo_tcp_server_t;

/** 处理、驱动、整轮调度、自动服务或整批清理在途时，同 server 的普通可变入口（含释放/监听/准入）均拒绝 BUSY；观察仍允许。
 * Reactor-only 重入保护不提供跨线程同步，独立 server 可嵌套。 */

/** 四项必须显式提供，无默认值，调用期间借用后按值保存。 */
typedef struct vireo_tcp_server_options {
    size_t connection_capacity; /**< 1..MAX_CONNECTIONS，loop 注册容量派生为此值加一。 */
    size_t event_capacity;      /**< 1..EVENT_LOOP_MAX_EVENTS，独立于连接数量。 */
    size_t max_memory_bytes;    /**< 1..MAX_MEMORY，计 control/客户元数据、完整 loop、pool 和可选 listener。 */
    size_t max_buffer_bytes;    /**< 1..CONNECTION_POOL_MAX_BUFFER_MEMORY，不预申请客户区。 */
} vireo_tcp_server_options_t;

/** 自动准入的数值配置；只影响此后自动接入，不改已有客户。 */
typedef struct vireo_tcp_server_admission_options {
    vireo_connection_options_t connection; /**< 固定双容量均至少32，受原预算及全池额度。 */
    vireo_connection_flow_options_t flow; /**< 新客户登记后启用的原帧流水位策略。 */
} vireo_tcp_server_admission_options_t;

/** 数值副本不延长生命期，不暴露依赖 owner、fd、槽位或 ABI。 */
typedef struct vireo_tcp_server_info {
    size_t connection_capacity;
    size_t event_capacity;
    size_t registration_capacity; /**< connection_capacity+1，内部唤醒不占客户注册槽。 */
    size_t server_allocation_bytes; /**< 本层 control 与固定客户元数据，不包含依赖。 */
    size_t client_slots_bytes;      /**< server_allocation_bytes 的表子集，不另加总。 */
    size_t registered_connections; /**< 成功登记且未注销的客户数，独立于池拥有数量。 */
    size_t loop_allocation_bytes;   /**< 公开 loop 的完整申请，已包含 epoll。 */
    size_t pool_allocation_bytes;   /**< 公开 connection_pool 的完整申请，已包含基础 pool。 */
    size_t listener_allocation_bytes; /**< 已收纳 acceptor 的实际申请，未收纳为零。 */
    size_t allocation_bytes;       /**< server+loop+pool+listener 受检合计，不另加 slots。 */
    bool listener_owned;
    bool listener_bound;
    bool listener_read_enabled;
    uint32_t listener_last_events; /**< 最后通知位；不是任务队列或存活证明。 */
    size_t max_memory_bytes;
    size_t max_buffer_bytes;
    size_t connection_count;       /**< 当前池拥有的客户数量。 */
    size_t available_connections;
    size_t buffer_capacity_bytes;  /**< 池拥有客户的固定双容量合计，含空余字节。 */
    bool processing_active;        /**< 正在同步处理阶段；时点快照，不是线程同步。 */
    bool driving_active;           /**< 整次客户驱动在途；不扩大 processing_active 的含义。 */
    bool scheduling_active;        /**< 整轮等待及各客户驱动在途，非跨线程同步。 */
    size_t pending_clients;        /**< 当前去重待办数，不证明完整帧或就绪仍成立。 */
    bool running_active;           /**< 整次run包含逐轮回调，普通Reactor重入标记。 */
    bool stop_requested;           /**< loop永久停止意图的原子快照，不代表资源已释放。 */
    bool serving_active;           /**< 整次自动服务含压力同步/等待/准入，非线程锁。 */
    bool admission_enabled;        /**< 已启用自动准入配置，必有自有绑定监听。 */
    vireo_connection_options_t admission_connection_options; /**< 启用时新客户构造值，停用语义零。 */
    vireo_connection_flow_options_t admission_flow_options; /**< 启用时新客户水位，非已有客户快照。 */
    size_t admission_pair_bytes;   /**< 新客户固定双容量合计，非字节积压。 */
    bool admission_connection_limited; /**< 按当前真账已无客户名额，停用时false。 */
    bool admission_buffer_limited; /**< 余固定额度不足一新客户，停用时false。 */
    bool admission_read_desired;   /**< 当前配置/真账推导值，可不同于已提交实际开关。 */
    bool shutdown_active;          /**< 整批客户清理在途，普通 Reactor 重入标记。 */
    size_t shutdown_next_slot;     /**< 下一批起始槽，始终小于 connection_capacity。 */
    bool auto_release_ready;       /**< 显式服务轮READY归还模式，默认false，非关闭策略。 */
    bool auto_close_policy;        /**< 默认false的服务轮EOF/实际网络错误关闭策略。 */
    bool closing_active;           /**< 整个关闭请求批次在途，非跨线程同步。 */
    size_t close_next_slot;         /**< 独立关闭扫描游标，始终小于连接容量。 */
} vireo_tcp_server_info_t;

/** 本层失败阶段；返回分类和依赖原诊断分别保留。 */
typedef enum vireo_tcp_server_stage {
    VIREO_TCP_SERVER_STAGE_NONE = 0,
    VIREO_TCP_SERVER_STAGE_ALLOCATE_CONTROL = 1,
    VIREO_TCP_SERVER_STAGE_CREATE_LOOP = 2,
    VIREO_TCP_SERVER_STAGE_INSPECT_LOOP = 3,
    VIREO_TCP_SERVER_STAGE_CREATE_POOL = 4,
    VIREO_TCP_SERVER_STAGE_INSPECT_POOL = 5,
    VIREO_TCP_SERVER_STAGE_DESTROY_POOL = 6,
    VIREO_TCP_SERVER_STAGE_DESTROY_LOOP = 7,
    VIREO_TCP_SERVER_STAGE_INSPECT_LISTENER = 8,
    VIREO_TCP_SERVER_STAGE_DESTROY_LISTENER = 9,
    VIREO_TCP_SERVER_STAGE_INSPECT_RESOURCES = 10
} vireo_tcp_server_stage_t;

/**
 * 独立按值诊断，不拥有资源。主失败不被回滚错误覆盖；成功/前置拒绝语义成员全零。
 * cleanup_result 为 OK 表示回滚未报告错误；否则保存首清理失败及其原诊断。
 */
typedef struct vireo_tcp_server_error {
    vireo_tcp_server_stage_t stage;
    vireo_event_loop_error_t loop_error;
    vireo_connection_pool_error_t pool_error;
    vireo_acceptor_error_t acceptor_error;
    vireo_result_t cleanup_result;
    vireo_tcp_server_stage_t cleanup_stage;
    vireo_event_loop_error_t cleanup_loop_error;
    vireo_connection_pool_error_t cleanup_pool_error;
    vireo_acceptor_error_t cleanup_acceptor_error;
} vireo_tcp_server_error_t;

/**
 * @brief 创建独占 loop 与空连接池，在真实总预算内完整发布空 server
 *
 * @param[in] options
 *     非空独立正选项，只借用到返回。
 * @param[in,out] out_server
 *     非空独立唯一 owner 地址，入口须为 NULL。
 * @param[out] error
 *     可空独立诊断，非空时每次覆盖全部语义成员。
 *
 * @retval VIREO_OK
 *     完整取得资源并发布 owner；无监听、客户注册、客户 buffer 或运行。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL、owner 非空或选项为零。
 * @retval VIREO_RESULT_RANGE
 *     选项超过硬限，或容器预算未容纳完整申请/正剩余。
 * @retval VIREO_RESULT_OVERFLOW
 *     本层受检计算不可表示，或依赖身份发放耗尽。
 * @retval VIREO_RESULT_NO_MEMORY
 *     本层或依赖申请失败，owner 保持，已获资源逆序清理。
 * @retval VIREO_RESULT_IO
 *     loop 系统失败，原诊断保持；没有自动重试或缩容。
 * @retval VIREO_RESULT_INTERNAL
 *     依赖快照违反公开容量/预算/空态不变量。
 *
 * @note 顺序：校验/受检→control 及固定客户表→剩余预算交 loop_create/inspect→扣真实申请
 *     →剩余预算交 pool_create/inspect→核对合计→最后发布。失败 pool→loop→control 清理，
 *     保留主要结果和首清理错误；只调用公开依赖，不获取 opaque sizeof。
 * @note 容器预算只计本层 control/固定客户表、完整 loop（含 epoll）和 pool（含基础池）；
 *     收纳监听后另计其实际控制申请；不含 allocator、内核、RSS、客户 connection control/双 buffer
 *     或池外临时对象。
 *     max_buffer_bytes 是池内固定双 buffer 容量额度，空态占用零、不预分配。
 * @note 全部存储须真实有效、对齐、独立且不重叠，不位于自有资源内；NULL 不验证坏地址。
 *     不暴露 loop/pool owner，复制句柄不增加所有权。保持入口 errno。
 * @note Reactor-only；不支持并发可变操作、signal handler、异步取消或 fork 后 exec 前使用。
 *     损坏对象/违约 hooks 不提供通用恢复保证；不负责非空服务器停机。
 */
vireo_result_t vireo_tcp_server_create(vireo_tcp_server_options_t const *options,
                                     vireo_tcp_server_t **out_server,
                                     vireo_tcp_server_error_t *error);

/**
 * @brief 核对公开依赖快照后，完整提交容量、监听/客户状态和实际申请数
 *
 * @param[in] server
 *     非空存活对象，调用期借用。
 * @param[out] out_info
 *     必需独立可写数值快照，失败保持全部字节。
 *
 * @retval VIREO_OK
 *     容量、预算及当前客户/登记计数不变量均成立，提交完整副本。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空；依赖拒绝原样返回。
 * @retval VIREO_RESULT_INTERNAL
 *     公开快照与创建时固定资源或当前客户计数不一致；依赖错误原分类返回。
 *
 * @note Reactor-only，无申请或资源借用，数值快照不冻结 ABI。所有路径保持入口 errno。
 * @note running_active含逐轮回调；stop_requested是合法永久意图，不代表客户/全部停止请求者已结束。
 */
vireo_result_t vireo_tcp_server_inspect(vireo_tcp_server_t const *server,
                                      vireo_tcp_server_info_t *out_info);

/**
 * @brief 销毁空池、loop 及可选监听，释放 control 并消费唯一 owner
 *
 * @param[in,out] server
 *     非空独立 owner 地址，*server 可为 NULL；先结束全部同对象使用。
 * @param[out] error
 *     可空独立诊断，每次覆盖。
 *
 * @retval VIREO_OK
 *     owner 已消费并 NULL，或空 owner 重复成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     owner 地址 NULL。
 * @retval VIREO_RESULT_BUSY
 *     监听回调在途、池仍有客户或依赖拒绝销毁，server/全部资源保持，不尝试 loop destroy；其他拒绝分类原样返回。
 * @retval VIREO_RESULT_IO
 *     loop 或 listener 单次关闭报错，仍清理全部资源并 NULL owner；保留主因和首后续清理错误。
 *
 * @note 先 pool 成功，再 loop 实际 destroy（OK/IO 消费），然后公开 forget 清监听本地绑定，
 *     单次 listener destroy，最后 control。pool 拒绝前不改变其他资源；须结束所有运行者、
 *     停止请求者及回调，stop 或 destroy BUSY 不满足 forget 前置。
 *     不自动逐监听DEL，不负责非空批量停机；运行停止本身不释放客户。
 *     OK/IO 均结束所有 server 别名；Reactor-only，保持入口 errno。
 * @note 同 server 的 client_process 在途时返回 BUSY，主要输出/owner/资源保持；观察仍可用。
 * @note 整次run含逐轮回调时BUSY；销毁前caller须结束所有运行者与全部停止请求者，停止不释放客户。
 */
vireo_result_t vireo_tcp_server_destroy(vireo_tcp_server_t **server,
                                      vireo_tcp_server_error_t *error);

/** 绑定诊断独立于资源诊断；返回依赖分类，并保存完整原原因。 */
typedef enum vireo_tcp_server_listener_stage {
    VIREO_TCP_SERVER_LISTENER_NONE = 0,
    VIREO_TCP_SERVER_LISTENER_BIND = 1,
    VIREO_TCP_SERVER_LISTENER_UPDATE = 2,
    VIREO_TCP_SERVER_LISTENER_UNBIND = 3
} vireo_tcp_server_listener_stage_t;

typedef struct vireo_tcp_server_listener_error {
    vireo_tcp_server_listener_stage_t stage;
    vireo_acceptor_loop_error_t acceptor_error;
} vireo_tcp_server_listener_error_t;

/**
 * @brief 在真实总预算内收纳一个已有且未绑定的监听 owner，不登记 loop
 *
 * @param[in,out] server
 *     非空存活对象，尚未拥有监听。
 * @param[in,out] listener_owner
 *     独立真实唯一 owner 地址，入口须非 NULL。
 * @param[out] error
 *     可空独立资源诊断，每次覆盖全部语义成员。
 *
 * @retval VIREO_OK
 *     最后转移 owner，caller 置 NULL；不申请内存或自动绑定。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL 或输入空 owner。
 * @retval VIREO_RESULT_BUSY
 *     server 已有监听，或输入已绑定/回调在途。
 * @retval VIREO_RESULT_RANGE
 *     本层及完整 loop/pool/acceptor 实际合计超预算。
 * @retval VIREO_RESULT_INTERNAL
 *     公开资源快照不一致；依赖拒绝原分类返回。
 * @retval VIREO_RESULT_OVERFLOW
 *     合计不可表示。
 *
 * @note 先检查状态、快照和受检总账，成功才发布；失败两 owner/资源保持。
 *     按实际申请计费，不累加 acceptor 的预算上限。收纳前临时对象属于 caller。
 *     成功后旧别名不授予再次销毁、更改或登记权；没有移回/替换接口。
 *     所有指针真实有效、独立对齐、不重叠且不在自有资源内；Reactor-only，保持 errno。
 * @note 同 server 的 client_process 在途时返回 BUSY，主要输出/owner/资源保持；观察仍可用。
 */
vireo_result_t vireo_tcp_server_adopt_listener(vireo_tcp_server_t *server,
                                              vireo_acceptor_t **listener_owner,
                                              vireo_tcp_server_error_t *error);

/**
 * @brief 将已拥有监听一次 ADD 到独占 loop，通知只记录最后就绪位
 *
 * @param[in,out] server
 *     非空存活对象，已收纳未绑定监听。
 * @param[in] read_enabled
 *     true 关注 READ，false 为零关注。
 * @param[out] error
 *     可空独立绑定诊断，每次覆盖。
 *
 * @retval VIREO_OK
 *     成功后发布绑定与开关，并清最后事件为零。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     server 为空。
 * @retval VIREO_RESULT_NOT_FOUND
 *     尚未收纳监听。
 * @retval VIREO_RESULT_BUSY
 *     已绑定；其他依赖分类原样返回。
 *
 * @note ADD 失败保持状态，监听仍归 server 所有。零关注仍可能通知 ERROR/HANGUP。
 *     内部固定回调无用户回调、不 accept、不构造连接。Reactor-only，保持 errno。
 * @note 同 server 的 client_process 在途时返回 BUSY，主要输出/owner/资源保持；观察仍可用。
 */
vireo_result_t vireo_tcp_server_bind_listener(vireo_tcp_server_t *server, bool read_enabled,
                                             vireo_tcp_server_listener_error_t *error);

/**
 * @brief 严格一次 MOD 更新 READ 开关，同值也执行 MOD
 *
 * @param[in,out] server
 *     非空存活且已绑定监听的对象。
 * @param[in] read_enabled
 *     READ 或零关注。
 * @param[out] error
 *     可空独立绑定诊断，每次覆盖。
 *
 * @retval VIREO_OK
 *     成功后发布新开关，最后事件保留历史观察。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     server 为空。
 * @retval VIREO_RESULT_NOT_FOUND
 *     未拥有或未绑定；依赖错误原分类返回。
 * @retval VIREO_RESULT_BUSY
 *     同 server 正在 client_process，主要输出与资源保持。
 *
 * @note 失败保留状态与完整原诊断，不重试或关闭。Reactor-only，保持 errno。
 * @note 同 server 的 client_process 在途时返回 BUSY，主要输出/owner/资源保持；观察仍可用。
 */
vireo_result_t vireo_tcp_server_set_listener_read_enabled(vireo_tcp_server_t *server,
                                                         bool read_enabled,
                                                         vireo_tcp_server_listener_error_t *error);

/**
 * @brief 严格一次 DEL 结束绑定，保留监听所有权
 *
 * @param[in,out] server
 *     非空存活对象。
 * @param[out] error
 *     可空独立绑定诊断，每次覆盖。
 *
 * @retval VIREO_OK
 *     已解绑或已有监听但未绑定；成功清开关和最后事件。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     server 为空。
 * @retval VIREO_RESULT_NOT_FOUND
 *     未拥有监听；依赖错误原分类返回。
 * @retval VIREO_RESULT_BUSY
 *     同 server 正在 client_process，主要输出与资源保持。
 *
 * @note DEL 失败保留绑定/资源，不自动重试；整体 destroy 可结束 owned loop 登记后清理。
 *     所有存储须真实有效独立且不重叠；Reactor-only，保持 errno。
 * @note 同 server 的 client_process 在途时返回 BUSY，主要输出/owner/资源保持；观察仍可用。
 */
vireo_result_t vireo_tcp_server_unbind_listener(vireo_tcp_server_t *server,
                                               vireo_tcp_server_listener_error_t *error);

/** 本轮 accept 成功数与实际 accept4 尝试数上限，均显式提供。 */
typedef struct vireo_tcp_server_admit_budget {
    size_t max_accepts;        /**< 1..MAX_CONNECTIONS，包含当前失败客户。 */
    size_t max_accept_syscalls; /**< 任意正 size_t，包含 transient、空队列和 IO。 */
} vireo_tcp_server_admit_budget_t;

typedef enum vireo_tcp_server_admit_stop {
    VIREO_TCP_SERVER_ADMIT_BATCH_LIMIT = 0,
    VIREO_TCP_SERVER_ADMIT_CONNECTION_LIMIT = 1,
    VIREO_TCP_SERVER_ADMIT_BUFFER_LIMIT = 2,
    VIREO_TCP_SERVER_ADMIT_CALL_LIMIT = 3,
    VIREO_TCP_SERVER_ADMIT_WOULD_BLOCK = 4,
    VIREO_TCP_SERVER_ADMIT_ERROR = 5
} vireo_tcp_server_admit_stop_t;

/** 本轮真实进度；accepted=admitted+rejected，错误也提交此前进度。 */
typedef struct vireo_tcp_server_admit_info {
    size_t accepted_count;
    size_t admitted_count;
    size_t rejected_count;
    size_t accept_calls;
    size_t transient_errors;
    vireo_tcp_server_admit_stop_t stop_reason;
} vireo_tcp_server_admit_info_t;

/** 数值副本，无 fd 或 connection 借用；不延长客户端生命。 */
typedef struct vireo_tcp_server_client_info {
    vireo_connection_info_t connection_info;
    uint32_t last_events; /**< 最后观察位，不是任务队列或存活证明。 */
    bool queued;           /**< 当前租约是否占一个待办位置。 */
    uint32_t pending_events; /**< 尚未出队的通知 OR；显式/缓存排队可为零。 */
} vireo_tcp_server_client_info_t;

typedef enum vireo_tcp_server_client_stage {
    VIREO_TCP_SERVER_CLIENT_NONE = 0,
    VIREO_TCP_SERVER_CLIENT_INSPECT_SERVER = 1,
    VIREO_TCP_SERVER_CLIENT_ACCEPT = 2,
    VIREO_TCP_SERVER_CLIENT_CREATE = 3,
    VIREO_TCP_SERVER_CLIENT_ADOPT = 4,
    VIREO_TCP_SERVER_CLIENT_LOOKUP = 5,
    VIREO_TCP_SERVER_CLIENT_ATTACH = 6,
    VIREO_TCP_SERVER_CLIENT_INSPECT = 7,
    VIREO_TCP_SERVER_CLIENT_DETACH = 8,
    VIREO_TCP_SERVER_CLIENT_RELEASE = 9,
    VIREO_TCP_SERVER_CLIENT_DESTROY_PENDING = 10,
    VIREO_TCP_SERVER_CLIENT_CLOSE_PENDING_FD = 11,
    VIREO_TCP_SERVER_CLIENT_RECEIVE = 12, /**< 客户接收失败，保留原 socket 原因。 */
    VIREO_TCP_SERVER_CLIENT_READ_PEEK = 13, /**< 客户只读观察失败。 */
    VIREO_TCP_SERVER_CLIENT_READ_CONSUME = 14, /**< 客户前缀消费失败。 */
    VIREO_TCP_SERVER_CLIENT_WRITE_ENQUEUE = 15, /**< 客户完整字节排队失败。 */
    VIREO_TCP_SERVER_CLIENT_SEND = 16, /**< 客户发送失败，保留原 socket 原因。 */
    VIREO_TCP_SERVER_CLIENT_FRAMES_PEEK = 17, /**< 客户帧识别失败，保留原 frame/codec 原因。 */
    VIREO_TCP_SERVER_CLIENT_HANDLER = 18, /**< 同步 handler 返回失败。 */
    VIREO_TCP_SERVER_CLIENT_RESPONSE = 19, /**< 响应描述或编码不合法。 */
    VIREO_TCP_SERVER_CLIENT_SET_INTERESTS = 20, /**< 手动关注依赖失败。 */
    VIREO_TCP_SERVER_CLIENT_FLOW_CONFIGURE = 21, /**< 水位配置依赖失败。 */
    VIREO_TCP_SERVER_CLIENT_FLOW_REFRESH = 22, /**< 水位刷新依赖失败。 */
    VIREO_TCP_SERVER_CLIENT_FLOW_DISABLE = 23, /**< 停用策略依赖失败。 */
    VIREO_TCP_SERVER_CLIENT_REQUEST_CLOSE = 24, /**< 关闭请求依赖失败；意图可能已提交。 */
    VIREO_TCP_SERVER_CLIENT_CLOSE_REFRESH = 25 /**< 关闭刷新依赖失败；逻辑阶段可能已变化。 */
} vireo_tcp_server_client_stage_t;

/** 各依赖原诊断独立保存，未参与字段语义为零；没有资源所有权。 */
typedef struct vireo_tcp_server_client_cause {
    vireo_tcp_server_client_stage_t stage;
    vireo_acceptor_error_t acceptor_error;
    vireo_connection_error_t connection_error;
    vireo_connection_pool_operation_error_t pool_error;
    vireo_connection_loop_error_t loop_error;
    int system_errno; /**< 本层 raw fd 单次 close 的原 errno，仅 IO 非零。 */
    vireo_connection_frame_error_t frame_error; /**< 独立帧原因，未参与时 NONE/NONE。 */
    vireo_result_t handler_result; /**< 原 handler 失败值；未知值也保留，不直接作 wire status。 */
    vireo_protocol_codec_issue_t response_codec_issue; /**< 响应基础校验原因，独立于请求帧错误。 */
} vireo_tcp_server_client_cause_t;

typedef struct vireo_tcp_server_client_error {
    vireo_tcp_server_client_cause_t primary;
    vireo_result_t cleanup_result;
    vireo_tcp_server_client_cause_t cleanup; /**< 首清理原因，不覆盖主因。 */
} vireo_tcp_server_client_error_t;

/**
 * @brief 按预算逐个接入、创建、收纳及登记，成功才发布数值租约
 *
 * @param[in,out] server
 *     存活且已拥有 listener，绑定及 READ 开关不限。
 * @param[in] options
 *     本轮显式公共 connection 选项，借用至返回，不保存地址。
 * @param[in] budget
 *     本轮显式双预算，不含 connection 查询或清理调用。
 * @param[out] out_clients
 *     独立数组，有效前缀 min(max_accepts,capacity) 三字段须全零。
 * @param[in] capacity
 *     数组容量，1..MAX_CONNECTIONS。
 * @param[out] out_info
 *     必需独立本轮统计，参数拒绝保持全部字节。
 * @param[out] error
 *     可空独立诊断，每次覆盖全部语义成员。
 *
 * @retval VIREO_OK
 *     批次、名额、固定 buffer 额度、调用预算或实际空队列正常停止。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL、零双预算或有效输出前缀非空。
 * @retval VIREO_RESULT_RANGE
 *     容量/选项超界，或单客户固定双容量超过全池上限。
 * @retval VIREO_RESULT_NOT_FOUND
 *     尚未拥有 listener。
 * @retval VIREO_RESULT_OVERFLOW
 *     容量受检合计/依赖身份不可表示或耗尽。
 * @retval VIREO_RESULT_NO_MEMORY
 *     客户申请失败，当前客户清理，原成功前缀保持。
 * @retval VIREO_RESULT_IO
 *     系统失败，原原因与真实部分进度保持，不自动重试。
 * @retval VIREO_RESULT_INTERNAL
 *     公开依赖不变量异常；其他依赖分类原样返回。
 * @retval VIREO_RESULT_BUSY
 *     同 server 正在 client_process，主要输出与资源保持。
 *
 * @note 先完整校验，再按批次→名额→剩 buffer→剩调用检查，每次至多一个未发布 fd。
 *     create→pool adopt（未绑定）→短期 lookup→READ|PEER_WRITE_CLOSED attach→输出租约。
 *     首失败停止，仅按当前 owner 清理失败客户；之前成功客户/租约不回滚。
 *     合法操作失败也提交统计，只写 admitted 前缀，未写槽和尾部保持。
 * @note 三元租约只用于存储有效性，不授予隐藏 pool/connection 所有权、fd 或异步身份。
 *     客户回调只记录最后事件，不自动收发/调水位/accept，不公开运行或 handler。
 * @note 元数据在 create 固定申请；每个 connection 仍真实申请双 buffer/control，
 *     两预算不代表内核、allocator、RSS 或 connection 控制总额，无硬实时/公平保证。
 *     指针真实有效对齐、独立不重叠且非自有资源；Reactor-only，保持入口 errno。
 * @note 同 server 的 client_process 在途时返回 BUSY，主要输出/owner/资源保持；观察仍可用。
 */
vireo_result_t vireo_tcp_server_admit_batch(vireo_tcp_server_t *server,
    vireo_connection_options_t const *options, vireo_tcp_server_admit_budget_t const *budget,
    vireo_connection_pool_lease_t *out_clients, size_t capacity,
    vireo_tcp_server_admit_info_t *out_info, vireo_tcp_server_client_error_t *error);

/**
 * @brief 验证当前租约后提交客户的按值状态和最后通知位
 *
 * @param[in] server
 *     非空存活对象，仅调用期间借用。
 * @param[in] client
 *     本 server 的当前 pool 数值租约。
 * @param[out] out_info
 *     必需独立按值输出，失败保持全部字节。
 *
 * @retval VIREO_OK
 *     当前客户快照完整提交，不提供资源借用。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL、畸形或跨池租约。
 * @retval VIREO_RESULT_RANGE
 *     同池槽号越界。
 * @retval VIREO_RESULT_NOT_FOUND
 *     全零、空槽或旧代际。
 * @retval VIREO_RESULT_INTERNAL
 *     公开快照与本层元数据不一致；依赖分类原样返回。
 *
 * @note 无分配/系统调用，不延长生命期。Reactor-only，保持入口 errno。
 */
vireo_result_t vireo_tcp_server_client_inspect(vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_client_info_t *out_info);

/**
 * @brief 显式注销并立即归还客户，消费型关闭 IO 仍退款且清租约
 *
 * @param[in,out] server
 *     非空存活对象，全部本客户借用须结束。
 * @param[in,out] client
 *     必需独立当前数值租约地址，OK/消费型 IO 三字段清零。
 * @param[out] error
 *     可空独立诊断，每次覆盖。
 *
 * @retval VIREO_OK
 *     单次 DEL 后 pool release 完成，名额/容量退还。
 * @retval VIREO_RESULT_IO
 *     DEL 失败保持绑定/资源；关闭 IO 则已消费并退款，读阶段辨别。
 * @retval VIREO_RESULT_BUSY
 *     客户回调在途保持；依赖归还拒绝原分类返回。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL、畸形或跨池租约。
 * @retval VIREO_RESULT_RANGE
 *     同池槽号越界。
 * @retval VIREO_RESULT_NOT_FOUND
 *     全零、空槽或旧代际。
 * @retval VIREO_RESULT_INTERNAL
 *     不变量异常，损坏对象/违约 hooks 无通用恢复。
 *
 * @note 已解绑时不再 DEL；DEL 成功后归还拒绝保留租约及真实已解绑状态，不 ADD 回滚。
 *     显式归还可放弃未发数据，不提供 drain/理由/deadline；非空 server destroy 仍 BUSY。
 *     消费后全部旧租约/借用失效，不 retry close。指针有效独立不重叠，Reactor-only/errno 保持。
 * @note 同 server 的 client_process 在途时返回 BUSY，主要输出/owner/资源保持；观察仍可用。
 */
vireo_result_t vireo_tcp_server_release_client(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t *client, vireo_tcp_server_client_error_t *error);

/**
 * @brief 按当前租约和显式双预算接收客户原始字节
 *
 * @param[in,out] server
 *     非空存活资源根，仅所属 Reactor 使用，不转移所有权。
 * @param[in] client
 *     本 server 当前存储租约；不要求仍绑定或 last_events 就绪。
 * @param[in] budget
 *     非空公开 connection 接收预算，两值均须正，借用至返回。
 * @param[out] out_info
 *     必需独立公开接收统计；参数/租约拒绝保持，已开始的 IO/INTERNAL 提交真实进度。
 * @param[out] error
 *     可空独立客户诊断，每次覆盖；失败保存 LOOKUP 或 RECEIVE 与完整原 socket 原因。
 *
 * @retval VIREO_OK
 *     EAGAIN、EOF、满区或预算正常停止，已收字节缓存在目标客户。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空、畸形或跨池租约。
 * @retval VIREO_RESULT_RANGE
 *     预算为零或同池槽号越界；保持统计和读借用。
 * @retval VIREO_RESULT_NOT_FOUND
 *     全零、空槽或过期代际。
 * @retval VIREO_RESULT_BUSY
 *     客户已请求关闭；保持统计、缓冲与借用。
 * @retval VIREO_RESULT_IO
 *     包括 EINTR，不重试，保留之前字节/统计及原 errno。
 * @retval VIREO_RESULT_INTERNAL
 *     公开依赖不变量异常，已开始操作仍沿依赖报告进度。
 *
 * @note 先校验参数和当前租约，只借 connection 至返回。合法 receive 先结束该客户
 *     全部旧读借用（含零进度/IO），参数/租约拒绝不结束；其他客户借用不受影响。
 * @note 无扩容或运行期新分配，不解码、刷新事件关注/flow、关闭或归还客户。
 *     EOF 永久记录但保留未读区且仍可发送；双预算不证明全局公平或硬实时。
 * @note 存储真实有效对齐、独立不重叠且非自有资源；Reactor-only，保持入口 errno。
 * @note 同 server 的 client_process 在途时返回 BUSY，主要输出/owner/资源保持；观察仍可用。
 */
vireo_result_t vireo_tcp_server_client_receive(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_connection_receive_budget_t const *budget,
    vireo_connection_receive_info_t *out_info, vireo_tcp_server_client_error_t *error);

/**
 * @brief 按当前租约短期只读借用客户全部未消费字节
 *
 * @param[in] server
 *     非空存活资源根，仅调用期间借用。
 * @param[in] client
 *     当前本 server 存储租约，不提供 connection 所有权。
 * @param[out] out_data
 *     必需独立指针输出，空态 NULL；字节归 connection，禁止修改/释放/交 worker。
 * @param[out] out_size
 *     必需独立长度输出，单位字节，空态零；两输出互不重叠。
 * @param[out] error
 *     可空独立客户诊断，每次覆盖，失败保存 LOOKUP 或 READ_PEEK。
 *
 * @retval VIREO_OK
 *     同时提交只读字节指针与长度，不判断完整帧，不消费或结束已有借用。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空、畸形或跨池租约。
 * @retval VIREO_RESULT_RANGE
 *     同池槽号越界。
 * @retval VIREO_RESULT_NOT_FOUND
 *     全零、空槽或旧代际。
 * @retval VIREO_RESULT_INTERNAL
 *     公开依赖不变量异常；其他依赖分类原样返回。
 *
 * @note 失败两输出全部保持。借用至同客户下一合法 receive（含零进度/IO）、成功
 *     consume（含0）或 release 实际消费（含关闭IO）；复制指针或 lease 不延长生命。
 *     inspect/peek/enqueue/send、失败 consume/参数拒绝及其他客户操作不结束该借用。
 * @note 不分配/扩容/系统调用；存储有效独立且不重叠资源。Reactor-only，保持 errno。
 */
vireo_result_t vireo_tcp_server_client_read_peek(vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, uint8_t const **out_data, size_t *out_size,
    vireo_tcp_server_client_error_t *error);

/**
 * @brief 消费当前客户已经处理的接收前缀
 *
 * @param[in,out] server
 *     非空存活资源根，全部本客户读借用使用须先结束。
 * @param[in] client
 *     本 server 当前有效租约。
 * @param[in] size
 *     字节数，0..当前 readable_size；零是成功空操作。
 * @param[out] error
 *     可空独立客户诊断，每次覆盖，失败保存 LOOKUP 或 READ_CONSUME。
 *
 * @retval VIREO_OK
 *     前缀已消费，顺序保持，任何成功含0都结束本客户全部旧读借用。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     server 为空、畸形或跨池租约。
 * @retval VIREO_RESULT_RANGE
 *     同池槽越界或 size 超未读长度，读区/借用保持。
 * @retval VIREO_RESULT_NOT_FOUND
 *     全零、空槽或过期租约。
 * @retval VIREO_RESULT_INTERNAL
 *     公开依赖不变量异常；其他依赖分类原样返回。
 * @retval VIREO_RESULT_BUSY
 *     同 server 正在 client_process，主要输出与资源保持。
 *
 * @note 不清 EOF/写区、不缩容/清零/关闭或刷新关注；由 caller 保证此前处理已完成。
 *     其他客户借用保持，pool 名额和固定容量额度不变。Reactor-only，保持入口 errno。
 * @note 同 server 的 client_process 在途时返回 BUSY，主要输出/owner/资源保持；观察仍可用。
 */
vireo_result_t vireo_tcp_server_client_read_consume(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, size_t size, vireo_tcp_server_client_error_t *error);

/**
 * @brief 将调用期借用字节完整复制到目标客户的固定待发 FIFO
 *
 * @param[in,out] server
 *     非空存活资源根，不转移客户/资源所有权。
 * @param[in] client
 *     本 server 当前有效租约。
 * @param[in] bytes
 *     size>0 须非空真实可读且稳定，允许有效读借用；不与对象/写区/诊断重叠。
 * @param[in] size
 *     字节数，0 可配 NULL；成功后不保存输入地址。
 * @param[out] error
 *     可空独立诊断，每次覆盖，失败保存 LOOKUP 或 WRITE_ENQUEUE/原 connection 原因。
 *
 * @retval VIREO_OK
 *     全部复制或合法空操作，caller 原字节可随后释放/更改。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     server 为空、非零 size 配 NULL、畸形或跨池租约。
 * @retval VIREO_RESULT_RANGE
 *     同池槽越界或单段超固定写容量，普通拒绝保持整个队列。
 * @retval VIREO_RESULT_NOT_FOUND
 *     全零、空槽或旧代际。
 * @retval VIREO_RESULT_OVERFLOW
 *     pending+size 不可表示，先于写容量检查。
 * @retval VIREO_RESULT_BUSY
 *     当前空余总量不足或客户已关闭；不部分复制。
 * @retval VIREO_RESULT_INTERNAL
 *     公开依赖不变量异常；其他分类原样返回。
 *
 * @note 只在需要且容量足够时整理写区，无扩容/分配/发送/编码/关注刷新。
 *     不改变读区或结束读借用；成功后再 consume 不删除独立待发副本。
 *     pool 名额与固定容量额度保持；Reactor-only，所有路径恢复入口 errno。
 * @note 同 server 的 client_process 在途时返回 BUSY，主要输出/owner/资源保持；观察仍可用。
 */
vireo_result_t vireo_tcp_server_client_write_enqueue(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, uint8_t const *bytes, size_t size,
    vireo_tcp_server_client_error_t *error);

/**
 * @brief 按当前租约和双正预算发送，只消费内核确认的 FIFO 前缀
 *
 * @param[in,out] server
 *     非空存活资源根，仅所属 Reactor 使用。
 * @param[in] client
 *     本 server 当前存储租约；不以历史就绪位或是否仍绑定为前置。
 * @param[in] budget
 *     非空公开 connection 发送预算，两值正，借用至返回。
 * @param[out] out_info
 *     必需独立公开发送统计；参数/租约拒绝保持，开始后的 IO/INTERNAL 提交真实进度。
 * @param[out] error
 *     可空独立客户诊断，每次覆盖，失败保存 LOOKUP 或 SEND/原 socket 原因。
 *
 * @retval VIREO_OK
 *     空队列、EAGAIN 或预算停止，不保证对端应用已经读取。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空、畸形或跨池租约。
 * @retval VIREO_RESULT_RANGE
 *     零预算或同池槽越界。
 * @retval VIREO_RESULT_NOT_FOUND
 *     全零、空槽或过期代际。
 * @retval VIREO_RESULT_BUSY
 *     客户逻辑关闭阶段 READY，统计/队列保持。
 * @retval VIREO_RESULT_IO
 *     EINTR/EPIPE 等系统错，不重试，保留此前进度和未发队列。
 * @retval VIREO_RESULT_INTERNAL
 *     公开依赖或数量异常，进度沿原依赖合同报告。
 *
 * @note 复用 MSG_DONTWAIT|MSG_NOSIGNAL、请求<=min(pending,余字节预算,4096)；
 *     空队列先于字节/次数预算，失败调用计次数，正返回即消费确认数量。
 * @note 无分配/扩容/事件关注或关闭刷新，不改变读区/EOF/读借用/池名额或固定额度。
 *     不自动归还或关闭客户。有效独立不重叠存储；Reactor-only，保持入口 errno。
 * @note 同 server 的 client_process 在途时返回 BUSY，主要输出/owner/资源保持；观察仍可用。
 */
vireo_result_t vireo_tcp_server_client_send(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_connection_send_budget_t const *budget,
    vireo_connection_send_info_t *out_info, vireo_tcp_server_client_error_t *error);

/**
 * @brief 按当前租约查看有界完整帧前缀，不消费读缓冲
 *
 * @param[in] server
 *     非空存活资源根，仅调用期借用；客户须仍由本 server 拥有。
 * @param[in] client
 *     当前公开数值租约，每次验证池、槽及代际；不要求历史就绪或仍绑定。
 * @param[in] options
 *     非空独立策略，显式 REQUEST 或 RESPONSE；max_frame_bytes 含 32 字节头，
 *     为 32..min(读容量,16MiB+32)，启用 flow 时不得超过其帧上限。
 * @param[in] budget
 *     非空双正消息/字节上限，无默认值；max_bytes 至少容纳 max_frame_bytes。
 * @param[out] views
 *     调用者拥有的非空数组，至少 view_capacity 条有效可写记录；只写有效前缀。
 * @param[in] view_capacity
 *     任意正 size_t 容量，与消息/字节预算共同限制本轮，不代表内部预分配。
 * @param[out] out_info
 *     必需独立统计；解析错误仍报告此前已验证的 frame_count/frame_bytes。
 * @param[out] error
 *     可空独立诊断，每次覆盖；失败阶段及原 frame_error 独立保存，不是 errno。
 *
 * @retval VIREO_OK
 *     停于半帧等待、空 EOF、双预算或输出容量；不表示业务处理或全部校验完成。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需指针为空、方向未知或跨池/畸形租约；views/info 保持。
 * @retval VIREO_RESULT_RANGE
 *     零容量/预算、非法帧上限、字节预算不足，或租约槽越界；views/info 保持。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空租约、已归还或旧代际；不调用帧识别，views/info 保持。
 * @retval VIREO_RESULT_PROTOCOL
 *     头/所选基础语义/CRC 非法、整帧超本客户上限或 EOF 残帧；保留原原因和有效前缀。
 * @retval VIREO_RESULT_INTERNAL
 *     公开依赖不变量或受检计算异常；已报告进度原样保留，损坏对象无通用修复。
 *
 * @note 所有记录的 header 按值，body 只读借用，空 body 为 NULL/0；不得修改/释放/交 worker。
 *     同客户下一合法 receive（含零进度/IO）、成功 consume（含0）或 release 消费（含关闭IO）
 *     结束全部旧 body 借用；一次消费结束整批借用。其他客户操作、观察/peek/enqueue/send
 *     不结束也不延长；处理完前缀再消费，若逐帧消费则必须重新取得后续 view。
 * @note 读区始终不变，不自动消费、compact、recv、回调、重同步、关闭或归还；重复 peek 重新校验。
 *     先消息预算/输出容量再数据/EOF；头 decode/基础验证/整帧上限后检查整帧字节预算，
 *     完整 body 后才 CRC。预算停止不探查后续全部错误，未写数组尾部保持。
 * @note 基础验证不包括命令专属 body/schema/鉴权，CRC 不认证身份；不自动编码响应或同步关注。
 *     所有输入/输出/诊断须有效、对齐、独立不重叠且不在自有资源内；Reactor-only，保持入口 errno。
 */
vireo_result_t vireo_tcp_server_client_frames_peek(vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, vireo_connection_frame_options_t const *options,
    vireo_connection_frame_budget_t const *budget, vireo_connection_frame_view_t *views,
    size_t view_capacity, vireo_connection_frame_info_t *out_info,
    vireo_tcp_server_client_error_t *error);

/** 两项均为含 32 字节头的显式单帧上限；不改变客户固定容量。 */
typedef struct vireo_tcp_server_process_options {
    size_t max_request_frame_bytes;  /**< 32..min(读容量, 协议最大 body+32)。 */
    size_t max_response_frame_bytes; /**< 32..min(写容量, 协议最大 body+32)。 */
} vireo_tcp_server_process_options_t;

/** 三项均为显式正值；每次调用 handler 前以最大帧作保守预留。 */
typedef struct vireo_tcp_server_process_budget {
    size_t max_messages;       /**< handler 次数上限，不代表 CPU 时间上限。 */
    size_t max_request_bytes;  /**< 至少最大请求整帧，按已消费实际 wire 字节累计。 */
    size_t max_response_bytes; /**< 至少最大响应整帧，按已排队实际 wire 字节累计。 */
} vireo_tcp_server_process_budget_t;

/** handler 只填写此按值描述和借用工作区的 body，不填写 wire header。 */
typedef struct vireo_tcp_server_reply {
    vireo_status_t status;    /**< 已知协议状态；业务拒绝也以 handler OK 返回。 */
    size_t body_size;         /**< 已初始化 body 字节数，不能超过给定 body_capacity。 */
    uint32_t session_handle;  /**< 响应 Session 值；初始化为请求值，不代替鉴权。 */
    uint32_t task_handle;     /**< 响应 task 值；初始化为请求值，不实现任务设施。 */
} vireo_tcp_server_reply_t;

/**
 * @brief 在给定固定工作区生成一条 SINGLE 响应的 body 和按值描述
 *
 * @param[in] request
 *     非空已通过 REQUEST 基础/长度/完整性/CRC 的帧，视图与 body 只借用至回调返回。
 * @param[out] body
 *     caller 工作区的 body 段，只在回调期间可写；容量零时为不可解引用尾后地址。
 * @param[in] body_capacity
 *     最大响应整帧减 32；handler 须初始化报告的全部字节。
 * @param[in,out] reply
 *     独立描述，初始 OK/0 字节/请求 handles；成功后由 server 校验并编码。
 * @param[in,out] context
 *     可空 caller 借用 context，代码/context 须活到 client_process 或 client_drive 返回。
 *
 * @retval VIREO_OK
 *     描述和 body 可交 server 检查；协议业务拒绝用 reply.status 表达。
 * @return
 *     其他已知内部 result 停止本轮，当前请求不消费；未知值由 server 转为 INTERNAL。
 *
 * @note 必须有界、非阻塞、正常返回，不存留视图/body/reply 地址，不修改同 server。
 *     不释放工作区、不返回栈 body 指针、不执行 DB/文件/密码等阻塞或耗时业务。
 *     handler 失败不保证外部副作用回滚；server 不自动重试，不承诺恰好执行一次。
 */
typedef vireo_result_t (*vireo_tcp_server_sync_handler_t)(
    vireo_connection_frame_view_t const *request, uint8_t *body, size_t body_capacity,
    vireo_tcp_server_reply_t *reply, void *context);

/** 正常停止是本次边界，不推断未探查的余帧/错误/EOF。 */
typedef enum vireo_tcp_server_process_stop {
    VIREO_TCP_SERVER_PROCESS_NEED_MORE = 0, /**< 没有完整请求，等待更多字节。 */
    VIREO_TCP_SERVER_PROCESS_EOF = 1, /**< 已观察 EOF 且读区为空。 */
    VIREO_TCP_SERVER_PROCESS_MESSAGE_BUDGET = 2, /**< 消息次数预算耗尽。 */
    VIREO_TCP_SERVER_PROCESS_REQUEST_BUDGET = 3, /**< 剩请求字节不足最大请求整帧。 */
    VIREO_TCP_SERVER_PROCESS_RESPONSE_BUDGET = 4, /**< 剩响应字节不足最大响应整帧。 */
    VIREO_TCP_SERVER_PROCESS_WRITE_FULL = 5, /**< 写空余不足最大响应，不调用 handler。 */
    VIREO_TCP_SERVER_PROCESS_ERROR = 6 /**< 当前步骤失败，此前实际进度仍报告。 */
} vireo_tcp_server_process_stop_t;

/** 三种提交分别统计；异常消费失败时排队响应可比消费请求多一条。 */
typedef struct vireo_tcp_server_process_info {
    size_t handler_calls;           /**< 实际进入 handler 的次数，包括失败那次。 */
    size_t consumed_requests;       /**< 已成功消费请求数。 */
    size_t consumed_request_bytes;  /**< 已消费 wire 字节数。 */
    size_t enqueued_responses;      /**< 已完整复制入写队列的响应数。 */
    size_t enqueued_response_bytes; /**< 已排队 wire 字节数，不是发送数。 */
    vireo_tcp_server_process_stop_t stop_reason;
} vireo_tcp_server_process_info_t;

/**
 * @brief 显式有界处理当前客户的 REQUEST，完整排队 SINGLE 响应后才消费请求
 *
 * @param[in,out] server
 *     非空存活资源根；处理在途同对象全部可变入口及递归处理/销毁 BUSY，观察允许。
 * @param[in] client
 *     当前仍 owned 的公开数值租约，不要求就绪快照或仍绑定；客户须 OPEN。
 * @param[in] options
 *     非空独立两帧上限，入口复制；分别不能超过读/写容量及协议硬限。
 * @param[in] budget
 *     非空独立三正预算，入口复制；两字节预算至少相应最大整帧。
 * @param[in,out] wire_workspace
 *     必需 caller 独立可写固定区，至少最大响应整帧；回调只取得 body 段。
 * @param[in] workspace_capacity
 *     真实可写容量，不新增分配；仅前 max_response_frame_bytes 可变。
 * @param[in] handler
 *     非空同步回调，仅本次借用，遵守有界/返回/借用及修改限制。
 * @param[in,out] context
 *     可空借用 context，不保存至调用后。
 * @param[out] out_info
 *     必需独立统计；先验拒绝保持，进入处理后成功/失败均提交真实进度。
 * @param[out] error
 *     可空独立 client 诊断；请求帧/handler/响应 codec/排队/消费原因分别保留。
 *
 * @retval VIREO_OK
 *     NEED_MORE/空 EOF、三种预算或写空余正常停止；未消费请求仍在读区。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL 或非法租约；不访问 handler/workspace。
 * @retval VIREO_RESULT_RANGE
 *     零预算/非法上限/工作区不足/上限超客户容量，或 handler 报 body 超给定容量。
 * @retval VIREO_RESULT_BUSY
 *     同 server 在途或客户 closing；handler/依赖 BUSY 原样返回并报告已发生进度。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空/过期租约，主要输出保持。
 * @retval VIREO_RESULT_PROTOCOL
 *     请求 framing/CRC/EOF 残帧或响应 status 不合法，原独立原因保留。
 * @retval VIREO_RESULT_OVERFLOW
 *     响应长度受检运算不可表示；不消费当前请求。
 * @retval VIREO_RESULT_INTERNAL
 *     异常依赖快照/帧输出或未知 handler 返回值；其他已知 handler/依赖结果原样返回。
 * @retval VIREO_RESULT_IO
 *     handler 或依赖 IO 失败，保留原诊断/进度，不重试。
 * @retval VIREO_RESULT_NO_MEMORY
 *     handler 返回内存失败；本入口不做运行期分配。
 * @retval VIREO_RESULT_TIMEOUT
 *     handler 报超时；本入口不自动设置 deadline。
 * @retval VIREO_RESULT_CANCELLED
 *     handler 报协作取消，当前请求不消费。
 * @retval VIREO_RESULT_DATABASE
 *     handler 报依赖失败；禁止在 Reactor 内执行阻塞数据库操作。
 *
 * @note 顺序为消息预算→剩请求/响应预算各能容纳最大帧→peek 一条 REQUEST→写空余预检
 *     →handler→校验描述/编码/CRC→一次完整 enqueue→一次 consume。预算按实际提交累计，
 *     预留比较保守；未探查后面错误。不自动 recv/send/MOD/释放或实现业务命令。
 * @note server 固定 RESPONSE，无 MORE，回显 command/sequence，handles/status 来自 reply。
 *     workspace 在合法回调或编码后允许改变；排队完整复制，不保留 workspace 指针。
 *     每条消费后重取下一帧，成功消费结束该客户全部旧读/body 借用。
 * @note handler/描述/排队失败当前请求不消费；外部副作用不回滚。若排队成功后消费异常，
 *     统计分别报告已排响应和未消费请求，保留原消费分类，不能安全重放，caller 负责释放。
 *     不重试/自动关闭，损坏对象或违约 hooks 无通用恢复保证。本项没有资源 cleanup。
 * @note 指针须真实有效、独立对齐且互不重叠，workspace 不在自有读区或其他输入/输出中；
 *     代码/context/工作区到返回前存活。Reactor-only，入口 errno（包括 handler 修改）始终恢复。
 *     有限预算不证明 handler 耗时、硬实时、公平或完整 server 已完成。
 * @note 启用 flow 时 max_request_frame_bytes 不得超过 flow 的 max_frame_bytes；
 *     违反时处理前 RANGE，保持统计/工作区且不调用 handler。
 */
vireo_result_t vireo_tcp_server_client_process(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_process_options_t const *options,
    vireo_tcp_server_process_budget_t const *budget, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_process_info_t *out_info, vireo_tcp_server_client_error_t *error);

/**
 * @brief 手动更新当前客户的 LT 关注
 *
 * @param[in,out] server
 *     所属 Reactor 的非空存活资源根，只借用至返回。
 * @param[in] client
 *     当前按值数值租约，先公开 lookup 并核对当前槽，非 fd 或异步身份。
 * @param[in] interests
 *     READ/WRITE/PEER_WRITE_CLOSED 三位组合，零合法，未知位拒绝。
 * @param[out] error
 *     可空独立诊断；依赖非成功保存本操作阶段及完整原 connection-loop 原因，
 *     不混用 socket 原因或 raw-close errno；本层前置拒绝/成功语义清零。
 *
 * @retval VIREO_OK
 *     单次严格 MOD 成功后提交关注；同值也 MOD。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     server 为空或存在未知关注位。
 * @retval VIREO_RESULT_NOT_FOUND
 *     旧/空租约或客户未绑定。
 * @retval VIREO_RESULT_BUSY
 *     同 server 处理在途、已开启 flow 或已请求关闭。
 * @retval VIREO_RESULT_IO
 *     MOD 失败，原关注/资源保持，不自动重试。
 *
 * @note OPEN 下须先 flow_disable 才能手动控制；不收发或自动关闭。
 * @note 跨池租约 INVALID_ARGUMENT，槽越界 RANGE；其他依赖分类原样返回。
 * @note 输入/诊断存储有效独立正确对齐且不重叠；同 server handler 在途拒绝全部可变入口。
 * @note Reactor-only，无新分配/字节操作/自动重试；保持入口 errno 及读/帧借用期限。
 */
vireo_result_t vireo_tcp_server_client_set_interests(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, uint32_t interests, vireo_tcp_server_client_error_t *error);

/**
 * @brief 配置当前客户的帧流迟滞水位
 *
 * @param[in,out] server
 *     所属 Reactor 的非空存活资源根，只借用至返回。
 * @param[in] client
 *     当前按值数值租约，先公开 lookup 并核对当前槽，非 fd 或异步身份。
 * @param[in] options
 *     必需独立配置，仅调用期间借用，依赖成功时按值保存；32 <= max_frame_bytes <=
 *     min(读容量,协议最大整帧)，max_frame_bytes-1 <= read_low < read_high <=
 *     读容量，0 <= write_low < write_high <= 写容量。
 * @param[out] error
 *     可空独立诊断；依赖非成功保存本操作阶段及完整原 connection-loop 原因，
 *     不混用 socket 原因或 raw-close errno；本层前置拒绝/成功语义清零。
 *
 * @retval VIREO_OK
 *     从未锁状态按当前占用计算压力；必要一次 MOD 成功后提交全部策略。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     server/options 为空。
 * @retval VIREO_RESULT_RANGE
 *     任一帧上限/阈值不符合约束，策略保持。
 * @retval VIREO_RESULT_NOT_FOUND
 *     旧/空租约或客户未绑定。
 * @retval VIREO_RESULT_BUSY
 *     同 server 处理在途或客户已请求关闭。
 * @retval VIREO_RESULT_IO
 *     MOD 失败，旧配置/压力/关注保持；之前字节进度不回滚。
 *
 * @note 占用 >= high 锁定，已锁占用 <= low 解除，中间保持；重配置重置锁存。
 * @note 未 EOF 且两压力解除才关注 READ/PEER_WRITE_CLOSED；待发非空才 WRITE。
 * @note read_low 下界避免合法半帧被读压力滞留；缓存完整帧仍须上层继续调度。
 * @note 开启后手动关注 BUSY，framing/process 请求上限不能超过策略上限。
 * @note 跨池租约 INVALID_ARGUMENT，槽越界 RANGE；其他依赖分类原样返回。
 * @note 输入/诊断存储有效独立正确对齐且不重叠；同 server handler 在途拒绝全部可变入口。
 * @note Reactor-only，无新分配/字节操作/自动重试；保持入口 errno 及读/帧借用期限。
 */
vireo_result_t vireo_tcp_server_client_flow_configure(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_connection_flow_options_t const *options,
    vireo_tcp_server_client_error_t *error);

/**
 * @brief 按当前占用与 EOF 显式刷新水位关注
 *
 * @param[in,out] server
 *     所属 Reactor 的非空存活资源根，只借用至返回。
 * @param[in] client
 *     当前按值数值租约，先公开 lookup 并核对当前槽，非 fd 或异步身份。
 * @param[out] error
 *     可空独立诊断；依赖非成功保存本操作阶段及完整原 connection-loop 原因，
 *     不混用 socket 原因或 raw-close errno；本层前置拒绝/成功语义清零。
 *
 * @retval VIREO_OK
 *     关注变化才单次 MOD；相同关注不 MOD，仍提交新压力。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     server 为空。
 * @retval VIREO_RESULT_NOT_FOUND
 *     旧/空租约、未绑定或未启用 flow。
 * @retval VIREO_RESULT_BUSY
 *     同 server 处理在途或客户已请求关闭。
 * @retval VIREO_RESULT_IO
 *     MOD 失败，旧策略/压力/关注保持，实际字节进度保留。
 *
 * @note 旧 receive/process/consume/enqueue/send 不隐式刷新；调用者有界操作后显式同步。
 * @note 两压力只暂停通知，不禁止 OPEN 客户的显式 receive，也不暂停待发排空。
 * @note EOF 撤读关注但不丢缓存；缓存完整帧须安排续处理，不只等新就绪。
 * @note 跨池租约 INVALID_ARGUMENT，槽越界 RANGE；其他依赖分类原样返回。
 * @note 输入/诊断存储有效独立正确对齐且不重叠；同 server handler 在途拒绝全部可变入口。
 * @note Reactor-only，无新分配/字节操作/自动重试；保持入口 errno 及读/帧借用期限。
 */
vireo_result_t vireo_tcp_server_client_flow_refresh(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_client_error_t *error);

/**
 * @brief 停用帧流策略并保留当前关注
 *
 * @param[in,out] server
 *     所属 Reactor 的非空存活资源根，只借用至返回。
 * @param[in] client
 *     当前按值数值租约，先公开 lookup 并核对当前槽，非 fd 或异步身份。
 * @param[out] error
 *     可空独立诊断；依赖非成功保存本操作阶段及完整原 connection-loop 原因，
 *     不混用 socket 原因或 raw-close errno；本层前置拒绝/成功语义清零。
 *
 * @retval VIREO_OK
 *     清配置与压力，保留当前关注；不 MOD，未绑定或已禁用仍可重复成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     server 为空。
 * @retval VIREO_RESULT_NOT_FOUND
 *     旧/空租约。
 * @retval VIREO_RESULT_BUSY
 *     同 server 处理在途或客户已请求关闭。
 *
 * @note 要改变剩余关注，须随后显式 set_interests；成功 detach 也清 flow。
 * @note 跨池租约 INVALID_ARGUMENT，槽越界 RANGE；其他依赖分类原样返回。
 * @note 输入/诊断存储有效独立正确对齐且不重叠；同 server handler 在途拒绝全部可变入口。
 * @note Reactor-only，无新分配/字节操作/自动重试；保持入口 errno 及读/帧借用期限。
 */
vireo_result_t vireo_tcp_server_client_flow_disable(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_client_error_t *error);

/**
 * @brief 永久提交当前客户关闭意图并同步关注
 *
 * @param[in,out] server
 *     所属 Reactor 的非空存活资源根，只借用至返回。
 * @param[in] client
 *     当前按值数值租约，先公开 lookup 并核对当前槽，非 fd 或异步身份。
 * @param[in] mode
 *     DRAIN 或 IMMEDIATE；同模式可重复，DRAIN 可升 IMMEDIATE，逆向 BUSY。
 * @param[in] reason
 *     公开六个非 NONE 理由之一，首次合法请求记录后永久保持。
 * @param[out] error
 *     可空独立诊断；依赖非成功保存本操作阶段及完整原 connection-loop 原因，
 *     不混用 socket 原因或 raw-close errno；本层前置拒绝/成功语义清零。
 *
 * @retval VIREO_OK
 *     意图已提交，必要单次 MOD 成功或无需 MOD；未绑定不访问 loop。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     server 为空或 mode/reason 非法，不提交意图。
 * @retval VIREO_RESULT_NOT_FOUND
 *     旧/空租约。
 * @retval VIREO_RESULT_BUSY
 *     同 server 处理在途，或 IMMEDIATE 要求退回 DRAIN。
 * @retval VIREO_RESULT_IO
 *     MOD 失败；新意图/首理由/逻辑阶段仍有效，旧关注保持，可显式补同步。
 *
 * @note 最后响应先 enqueue 再 DRAIN；非空为 DRAINING/WRITE，空为 READY/0。
 * @note IMMEDIATE 为 READY/0，读写字节保留；关闭后 receive/enqueue/process/手动/flow BUSY。
 * @note 只有 OPEN/DRAINING 可 send；观察、帧查看及读消费仍允许，没有 reset。
 * @note 不 DEL/close/free/shutdown；READY 仍占名额和固定容量，须 release_client 收尾。
 * @note 不自动选择理由/期限，不保证对端收到；关闭关注优先于旧 flow 快照。
 * @note 跨池租约 INVALID_ARGUMENT，槽越界 RANGE；其他依赖分类原样返回。
 * @note 输入/诊断存储有效独立正确对齐且不重叠；同 server handler 在途拒绝全部可变入口。
 * @note Reactor-only，无新分配/字节操作/自动重试；保持入口 errno 及读/帧借用期限。
 */
vireo_result_t vireo_tcp_server_client_request_close(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_connection_close_mode_t mode,
    vireo_connection_close_reason_t reason, vireo_tcp_server_client_error_t *error);

/**
 * @brief 在有界发送后显式同步关闭阶段与关注
 *
 * @param[in,out] server
 *     所属 Reactor 的非空存活资源根，只借用至返回。
 * @param[in] client
 *     当前按值数值租约，先公开 lookup 并核对当前槽，非 fd 或异步身份。
 * @param[out] error
 *     可空独立诊断；依赖非成功保存本操作阶段及完整原 connection-loop 原因，
 *     不混用 socket 原因或 raw-close errno；本层前置拒绝/成功语义清零。
 *
 * @retval VIREO_OK
 *     按待发队列与永久模式更新阶段，关注变更才一次 MOD。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     server 为空。
 * @retval VIREO_RESULT_NOT_FOUND
 *     旧/空租约或客户仍 OPEN。
 * @retval VIREO_RESULT_BUSY
 *     同 server 处理在途。
 * @retval VIREO_RESULT_IO
 *     MOD 失败，新逻辑阶段仍有效、旧关注保持，不回滚此前已发送字节。
 *
 * @note send 不隐式刷新；发空后显式刷新才 DRAINING->READY 并撤 WRITE。
 * @note READY 不自动归还；release_client 沿一次 DEL->pool release，DEL 失败保留。
 * @note 非空 server destroy 仍 BUSY；未绑定对象无需 loop 操作，关闭状态不因解绑清除。
 * @note 跨池租约 INVALID_ARGUMENT，槽越界 RANGE；其他依赖分类原样返回。
 * @note 输入/诊断存储有效独立正确对齐且不重叠；同 server handler 在途拒绝全部可变入口。
 * @note Reactor-only，无新分配/字节操作/自动重试；保持入口 errno 及读/帧借用期限。
 */
vireo_result_t vireo_tcp_server_client_close_refresh(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_client_error_t *error);

/** 三阶段原预算独立按值复制；均显式正值，无默认或共享无限预算。 */
typedef struct vireo_tcp_server_drive_budget {
    vireo_connection_receive_budget_t receive;
    vireo_tcp_server_process_budget_t process;
    vireo_connection_send_budget_t send;
} vireo_tcp_server_drive_budget_t;

/** called 为 false 时对应统计是未调用的 typed 零值，不代表实际停止原因。 */
typedef struct vireo_tcp_server_drive_info {
    vireo_connection_receive_info_t receive;
    vireo_tcp_server_process_info_t process;
    vireo_connection_send_info_t send;
    bool receive_called;
    bool process_called;
    bool send_called;
    bool needs_processing; /**< 成功 OPEN 下的保守缓存续提示，不证明下一完整帧存在。 */
    bool ready_to_release; /**< 成功观察到READY；此drive本身不释放，服务轮可依显式模式归还。 */
} vireo_tcp_server_drive_info_t;

/** 独立组合阶段；不改变既有 client_stage 数值。 */
typedef enum vireo_tcp_server_drive_stage {
    VIREO_TCP_SERVER_DRIVE_NONE = 0,
    VIREO_TCP_SERVER_DRIVE_LOOKUP = 1,
    VIREO_TCP_SERVER_DRIVE_INSPECT = 2,
    VIREO_TCP_SERVER_DRIVE_PRE_SYNC = 3,
    VIREO_TCP_SERVER_DRIVE_RECEIVE = 4,
    VIREO_TCP_SERVER_DRIVE_PROCESS = 5,
    VIREO_TCP_SERVER_DRIVE_SEND = 6,
    VIREO_TCP_SERVER_DRIVE_FINAL_SYNC = 7
} vireo_tcp_server_drive_stage_t;

/** 主结果为函数返回值；补同步次错独立保存，不覆盖首因或误称资源清理。 */
typedef struct vireo_tcp_server_drive_error {
    vireo_tcp_server_drive_stage_t primary_stage;
    vireo_tcp_server_client_error_t primary_error;
    vireo_result_t sync_result; /**< OK 表示没有独立次错，只有末尾失败时它是主因。 */
    vireo_tcp_server_client_error_t sync_error;
} vireo_tcp_server_drive_error_t;

/**
 * @brief 对当前客户执行一轮有界收、同步处理、发与关注同步
 *
 * @param[in,out] server
 *     非空存活资源根；整轮驱动在途同 server 所有可变入口/递归处理/驱动/销毁 BUSY。
 * @param[in] client
 *     当前仍 owned 的数值租约，不要求 last_events 就绪；不转移资源或清租约。
 * @param[in] options
 *     非空独立原 process 两帧上限，入口复制；各为 32..min(实际容量, 协议硬限)。
 * @param[in] budget
 *     非空独立三原预算，入口复制；receive/send 双正，process 消息正且两字节预算各足够最大帧。
 * @param[in,out] wire_workspace
 *     非空独立响应工作区，仅本调用借用；沿原 handler/编码合同，进入处理后可改变。
 * @param[in] workspace_capacity
 *     至少 options 最大响应整帧；包括 DRAINING/READY 在内均要求共同参数有效。
 * @param[in] handler
 *     非空原同步 REQUEST/SINGLE handler；有界非阻塞、正常返回，不保留请求/工作区借用。
 * @param[in,out] context
 *     可空 caller context，仅借用至返回；独立 server 可嵌套，观察同 server 仍允许。
 * @param[out] out_info
 *     必需独立统计；前置拒绝保持，进入执行后提交各实际阶段的部分进度。
 * @param[out] error
 *     可空独立主/补同步诊断；完整原 socket/帧/handler/loop 原因按值保留。
 *
 * @retval VIREO_OK
 *     有界本轮完成，含 EAGAIN/EOF/容量或预算停止；不承诺全部请求或响应已完成。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空或原租约拒绝；主要输出/工作区保持，诊断可更新。
 * @retval VIREO_RESULT_RANGE
 *     预算/帧/容量/工作区拒绝，或 OPEN 请求上限超过 flow 上限；执行前保持输出。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空/过期租约，或 OPEN 未绑定/未启用 flow；不收发、处理或 MOD，输出保持。
 * @retval VIREO_RESULT_BUSY
 *     同 server 处理/驱动在途；不改变主要输出或资源。
 * @retval VIREO_RESULT_IO
 *     首收发/同步失败；原 errno 与真实进度保留，不重试、不自动关闭或归还。
 * @retval VIREO_RESULT_PROTOCOL
 *     原帧协议错误；当前帧不消费，此前处理进度保留。
 * @return
 *     其他依赖/handler 原分类沿旧合同返回，未知 handler 值转 INTERNAL 并保存原值。
 *
 * @note OPEN 须 live flow 绑定：先 flow_refresh/inspect，再仅未 EOF 且两压力均清时 receive；
 *     缓存 process 不因 READ 暂停被跳过，随后 send、一次 final flow_refresh、成功 inspect。
 *     DRAINING 只 send+close_refresh；READY 不收发/handler，仍 close_refresh 补同步。
 *     关闭分支可未绑定；不自动选关闭理由、DEL、release、close、shutdown 或退款。
 * @note 首 receive/process/send 错误停止后续数据阶段，但仍一次末尾同步；两错分别保存。
 *     pre-sync 或其后 inspect 失败不重复同步；只有末尾同步失败时它为主因。
 *     错误路径两个 hint 均 false；已发生字节/业务副作用不回滚，不承诺安全重放或恰好一次。
 * @note 成功 OPEN 且 process 因消息/请求字节/响应字节预算或 WRITE_FULL 停止，读区非空、
 *     发送后写空余足够最大响应时 needs_processing=true；不额外 peek/CRC 探查预算后帧。
 *     可保守多一次 NEED_MORE；空间不足时 false，靠 WRITE 推进。caller 须安排有界续轮，
 *     不能仅等新 READ，也不能递归或无限独占；本接口没有实际待办队列/全局公平/run-stop。
 * @note 所有入口保持 errno；Reactor-only，无运行期申请/扩容。读/帧借用只随实际合法 receive、
 *     成功 consume 或消费 release 到期；发送/策略和未执行的接收不新增失效条件。
 *     所有地址有效对齐、独立存活且不重叠，不位于对象自有资源内；NULL 检查不验证坏地址。
 */
vireo_result_t vireo_tcp_server_client_drive(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_process_options_t const *options,
    vireo_tcp_server_drive_budget_t const *budget, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_drive_info_t *out_info, vireo_tcp_server_drive_error_t *error);

/** 每轮最多服务客户数，显式 1..MAX_CONNECTIONS，不代表 CPU 时间。 */
typedef struct vireo_tcp_server_round_budget {
    size_t max_clients; /**< 与等待后待办数、结果数组容量共同限制本轮。 */
} vireo_tcp_server_round_budget_t;

/** 按值结果不授予 owner 或请求 body 借用；仅实际服务前缀会写入。 */
typedef struct vireo_tcp_server_turn_result {
    vireo_connection_pool_lease_t client; /**< 服务历史身份；released=true后不得继续使用。 */
    uint32_t events; /**< 本次出队前合并通知，非收发门禁，可为零。 */
    vireo_result_t result; /**< 该客户原 drive 结果，拒绝时 info 未调用字段为 typed 零。 */
    vireo_tcp_server_drive_info_t info; /**< 各 called/真实进度及缓存/释放提示。 */
    vireo_tcp_server_drive_error_t error; /**< 完整客户主因和独立补同步次错。 */
    bool release_attempted; /**< 此turn drive成功且READY后是否尝试一次归还。 */
    vireo_result_t release_result; /**< 独立归还分类；未尝试时OK，不覆盖drive result。 */
    bool released; /**< 实际消费owner并退款；消费型IO也为true。 */
    vireo_tcp_server_client_error_t release_error; /**< 原注销/归还完整诊断，非drive错误。 */
    bool close_checked; /**< 本turn启用策略并执行分类/观测；不代表发出关闭请求。 */
    bool close_attempted; /**< 实际调用一次request_close，IO也可能已经提交意图。 */
    vireo_result_t close_result; /**< 策略分类/观测/请求结果，未检查为OK，不覆盖drive。 */
    vireo_tcp_server_client_error_t close_error; /**< 策略原lookup/inspect/request_close独立原因。 */
    bool close_requeued; /**< 正常EOF新READY安排下轮成功drive，不计旧缓存hint。 */
} vireo_tcp_server_turn_result_t;

/** 一轮观察与有界客户计数，不无界累计各客户的字节统计。 */
typedef struct vireo_tcp_server_round_info {
    vireo_event_loop_run_info_t wait; /**< 原 loop 就绪/分发/过期/过滤计数，含监听通知。 */
    int effective_timeout_ms; /**< 已有待办时为零，否则 caller timeout。 */
    size_t queued_before_wait; /**< 入口已排队客户数。 */
    size_t queued_after_wait; /**< 通知结束后的待办数，冻结本轮最多一次的依据。 */
    size_t turn_count; /**< 实际 drive 次数及结果前缀长度，含最后失败客户。 */
    size_t succeeded_count; /**< drive 返回 OK 的客户数。 */
    size_t failed_count; /**< drive 返回失败的客户数，首错停轮因此至多一。 */
    size_t requeued_count; /**< 本轮成功缓存提示新回队次数，不计通知去重。 */
    size_t remaining_count; /**< 返回时仍在队列的客户数。 */
    size_t release_attempted_count; /**< 本轮成功READY turn的归还尝试数，受原turn上限约束。 */
    size_t released_count; /**< 本轮实际消费客户数，包含消费型关闭IO。 */
    size_t close_attempted_count; /**< 本轮实际request_close数，至多turn_count。 */
    size_t close_requeued_count; /**< 正常EOF新READY的生命周期续项数。 */
} vireo_tcp_server_round_info_t;

/** 独立调度错误阶段，不改变已有 client/drive 枚举。 */
typedef enum vireo_tcp_server_round_stage {
    VIREO_TCP_SERVER_ROUND_NONE = 0,
    VIREO_TCP_SERVER_ROUND_WAIT = 1,
    VIREO_TCP_SERVER_ROUND_DRIVE = 2,
    VIREO_TCP_SERVER_ROUND_QUEUE = 3,
    VIREO_TCP_SERVER_ROUND_RELEASE = 4, /**< drive成功后的注销/归还首错。 */
    VIREO_TCP_SERVER_ROUND_CLOSE = 5 /**< drive成功后策略观测/关闭请求失败。 */
} vireo_tcp_server_round_stage_t;

/** 原返回分类由函数给出，等待与客户双错各保留原诊断。 */
typedef struct vireo_tcp_server_round_error {
    vireo_tcp_server_round_stage_t stage; /**< 首个本层失败阶段；参数拒绝为 NONE。 */
    vireo_event_loop_error_t loop_error; /**< WAIT 时完整原 loop 原因。 */
    vireo_connection_pool_lease_t client; /**< DRIVE/CLOSE/RELEASE时客户历史身份，非owner。 */
    vireo_tcp_server_drive_error_t drive_error; /**< DRIVE 时完整原主/补同步原因。 */
    vireo_tcp_server_client_error_t client_error; /**< RELEASE时完整原注销/归还原因。 */
    vireo_result_t close_result; /**< CLOSE主错或DRIVE主错后的策略次错；无错为OK。 */
    vireo_tcp_server_client_error_t close_error; /**< 与close_result对应的完整策略原因。 */
} vireo_tcp_server_round_error_t;

/**
 * @brief 将当前 owned 客户安排到有界 FIFO，已有位置重复成功且不移位
 *
 * @param[in,out] server
 *     非空存活对象，Reactor-only；同 server 处理/驱动/调度在途 BUSY。
 * @param[in] client
 *     当前数值租约，不转移资源；允许 closing 或暂未绑定，能否 drive 在其 turn 验证。
 * @param[out] error
 *     可空独立 client 诊断，lookup 失败保留原分类，成功语义清零。
 *
 * @retval VIREO_OK
 *     恰一个排队位置，原排队客户顺序保持，不读取字节或执行 handler。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     server 为空、畸形或跨池租约；队列保持。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空、旧代际或已归还租约；队列保持。
 * @retval VIREO_RESULT_RANGE
 *     同池槽号越界；队列保持。
 * @retval VIREO_RESULT_BUSY
 *     同 server 在途，队列/资源保持。
 * @return
 *     其他公开 lookup 分类原样，队列不变量异常 INTERNAL。
 *
 * @note 无运行期申请、字节操作或关注修改；所有路径保持入口 errno。
 * @note 仅安排一次机会，不证明完整帧或绕过原 flow/关闭合同。释放实际消费才撤队。
 */
vireo_result_t vireo_tcp_server_schedule_client(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_client_error_t *error);

/**
 * @brief 一次等待后公平服务固定数量的待办客户，缓存续项排到下轮
 *
 * @param[in,out] server
 *     非空存活唯一资源根，整轮 scheduling_active 保护所有同 server 可变入口。
 * @param[in] timeout_ms
 *     -1 无限等待、0 立即、正相对毫秒；入口有待办强制 0，<-1 拒绝。
 * @param[in] options
 *     非空独立原 process 帧上限，入口复制；本轮共用，客户实际容量/flow 在其 turn 校验。
 * @param[in] drive_budget
 *     非空独立 M8 三预算，入口复制；每客户分别使用，不是共享无界额度。
 * @param[in] round_budget
 *     非空独立 max_clients 为 1..MAX_CONNECTIONS，入口复制。
 * @param[in,out] wire_workspace
 *     非空独立响应工作区，顺序供各 turn 借用，仅本次调用有效。
 * @param[in] workspace_capacity
 *     至少 options 最大响应整帧字节数，共同拒绝不改变工作区。
 * @param[in] handler
 *     非空原同步 handler，有界非阻塞正常返回，请求只借用至回调返回。
 * @param[in,out] context
 *     可空 caller context，只本次调用借用；独立 server 可嵌套。
 * @param[out] out_turns
 *     必需独立按值结果数组，只覆盖实际 turn_count 前缀，尾部保持。
 * @param[in] turn_capacity
 *     1..MAX_CONNECTIONS；与 round_budget、等待后 Q 取较小值。
 * @param[out] out_info
 *     必需独立总统计，共同参数/等待拒绝保持；开始调度后提交真实部分进度。
 * @param[out] error
 *     可空独立首因，WAIT 原 loop、DRIVE 原双诊断及独立 CLOSE/RELEASE 诊断。
 *
 * @retval VIREO_OK
 *     一轮有界服务完成，含空待办、预算停止、EAGAIN/EOF/半帧；不保证队列空或全部发送。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需指针为空或 timeout<-1，共同拒绝保持输出/工作区/队列。
 * @retval VIREO_RESULT_RANGE
 *     共同帧/预算/数组/工作区范围拒绝保持输出；某客户实际容量拒绝则报告该 turn 的前缀。
 * @retval VIREO_RESULT_BUSY
 *     同 server 在途拒绝，资源/主要输出保持。
 * @retval VIREO_RESULT_IO
 *     一次等待或客户收发/同步失败；读阶段区分输出保持与真实部分进度，不自动重试。
 * @retval VIREO_RESULT_INTERNAL
 *     队列不变量异常或原依赖内部失败；损坏对象/违约 hooks 无通用恢复。
 * @return
 *     其他原客户/handler 分类沿 drive 返回，包含 PROTOCOL/NOT_FOUND 等。
 *
 * @note 严格一次公开 loop 等待；内部通知只合并/去重入队，监听仍只记录最后事件，不自动 accept。
 *     冻结 min(等待后 Q,max_clients,turn_capacity) 个 turn，每客户本轮最多一次，成功缓存 hint 尾插。
 *     FIFO 提供轮转机会，不保证耗时公平；消息预算不能抢占一个阻塞 handler。
 * @note auto_close_policy默认false；开启时按真实EOF/请求帧/收发错误源选择关闭，
 *     原drive结果/双诊断不改，策略结果独立。成功EOF新READY仅下轮尾插，不改原READY hint。
 * @note 共同拒绝/等待失败不调用业务，主要输出/旧队列保持；成功等待后首 turn 错立即停轮，
 *     报告含失败项的进度，失败项不因错误自动回队，其余待办/成功续项保持。不回滚已发生副作用。
 *     后续新 kernel 通知仍可让失败客户入队；caller 先修复或释放再决定下一轮，不承诺恰好一次。
 * @note 只执行有限一轮，默认不自动配置flow或关闭/DEL/release；旧显式byte/process/drive不隐式排队。
 *     显式开启auto_release_ready时，成功READY turn一次归还；首释放错停轮，独立字段报告真实消费。
 *     默认READY仍须显式归还；成功/消费型IO撤队退款，拒绝保真实绑定/解绑状态。
 *     drive首错优先于策略次错，失败项不自动续排或归还；成功drive后策略错为CLOSE主因。
 * @note Reactor-only，runtime 无申请/扩容；观察同 server 允许，递归调度/驱动/处理/所有 mutable BUSY。
 *     地址有效、独立、对齐且不重叠。借用仅随实际 receive/consume/消费 release 到期，保持入口 errno。
 * @note run期间公共run_once递归BUSY；原共同参数拒绝后，已停止对象成功交付语义零统计，数组/workspace/Q保持。
 */
vireo_result_t vireo_tcp_server_run_once(vireo_tcp_server_t *server, int timeout_ms,
    vireo_tcp_server_process_options_t const *options,
    vireo_tcp_server_drive_budget_t const *drive_budget,
    vireo_tcp_server_round_budget_t const *round_budget, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_turn_result_t *out_turns, size_t turn_capacity,
    vireo_tcp_server_round_info_t *out_info, vireo_tcp_server_round_error_t *error);


/** 一轮共享数值配置，全部显式，入口复制；不保存调用者地址。 */
typedef struct vireo_tcp_server_serve_options {
    int timeout_ms; /**< -1/0/正毫秒；有既有待办仍按原round强制0。 */
    vireo_tcp_server_process_options_t process; /**< 原共同请求/响应帧上限，还须兼容新客户配置。 */
    vireo_tcp_server_drive_budget_t drive; /**< 每个既有客户分别使用的原三阶段预算。 */
    vireo_tcp_server_round_budget_t round; /**< 原本轮客户数预算，1..65535。 */
    vireo_tcp_server_admit_budget_t admit; /**< 本轮新accept成功数/系统尝试数双上限。 */
} vireo_tcp_server_serve_options_t;

/** 等待成功后真实阶段进度；未调用准入时以called区别typed零枚举。 */
typedef struct vireo_tcp_server_serve_info {
    vireo_tcp_server_round_info_t round; /**< 原客户轮次完整前缀统计。 */
    uint32_t listener_events; /**< 仅本次等待的监听通知OR，非历史last_events。 */
    bool admission_called; /**< 是否开始有界准入核心，可能零次accept。 */
    vireo_tcp_server_admit_info_t admission; /**< 原accepted/admitted/rejected/calls/transient/stop。 */
    size_t initialized_count; /**< 新owned前缀中已成功启用flow数量，<=admitted。 */
    bool sync_called; /**< 是否执行一次末尾压力同步，即使不需要MOD。 */
    bool listener_read_enabled; /**< 返回时已提交实际监听开关，不假称desired已生效。 */
} vireo_tcp_server_serve_info_t;

/** 独立组合阶段，不重排旧round/client/监听枚举。 */
typedef enum vireo_tcp_server_serve_stage {
    VIREO_TCP_SERVER_SERVE_NONE = 0, /**< 成功或共同前置拒绝，未报告执行阶段。 */
    VIREO_TCP_SERVER_SERVE_PRE_SYNC = 1, /**< 入口监听容量同步失败，未等待。 */
    VIREO_TCP_SERVER_SERVE_ROUND = 2, /**< 原等待或客户轮次主错误。 */
    VIREO_TCP_SERVER_SERVE_LISTENER_EVENT = 3, /**< 本次监听 ERROR/HANGUP，保留事件位。 */
    VIREO_TCP_SERVER_SERVE_ADMIT = 4, /**< 新客户接入或登记主错误，保留成功前缀。 */
    VIREO_TCP_SERVER_SERVE_INITIALIZE = 5, /**< 已登记客户 flow 初始化失败，租约仍 owned。 */
    VIREO_TCP_SERVER_SERVE_POST_SYNC = 6 /**< 仅末尾监听同步失败作为主因。 */
} vireo_tcp_server_serve_stage_t;

/** 主因和末尾压力同步错误分开，均按值而不拥有资源。 */
typedef struct vireo_tcp_server_serve_error {
    vireo_tcp_server_serve_stage_t stage; /**< 主要阶段；共同拒绝NONE。 */
    vireo_tcp_server_round_error_t round_error; /**< ROUND时原wait/drive双错及关闭/归还原因。 */
    vireo_tcp_server_client_error_t client_error; /**< ADMIT/INITIALIZE时原主/清理或flow原因。 */
    vireo_tcp_server_listener_error_t listener_error; /**< 主pre/post-sync的完整监听原诊断。 */
    vireo_connection_pool_lease_t client; /**< INITIALIZE时仍owned的失败客户，须修复或归还。 */
    uint32_t listener_events; /**< LISTENER_EVENT时原通知，无虚构system_errno。 */
    vireo_result_t sync_result; /**< 已有主因时首末尾同步失败，OK表示未报告次错。 */
    vireo_tcp_server_listener_error_t sync_error; /**< sync_result对应的完整原诊断。 */
} vireo_tcp_server_serve_error_t;

/**
 * @brief 配置新客户资源与帧流策略，并同步监听准入容量门禁
 *
 * @param[in,out] server
 *     非空存活资源根，须已拥有且绑定监听，仅Reactor调用。
 * @param[in] options
 *     非空独立connection/flow数值，成功按值保存，不改变已有客户。
 * @param[out] error
 *     可空独立监听诊断，MOD失败完整保存原原因。
 *
 * @retval VIREO_OK
 *     配置已发布，实际READ按当前名额/固定容量同步；重复合法配置允许。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空，主要状态保持。
 * @retval VIREO_RESULT_BUSY
 *     同 server 任一业务/调度/自动服务在途，资源和主要输出保持。
 * @retval VIREO_RESULT_RANGE
 *     新双容量至少32、原硬限/预算/flow范围或全池额度不满足。
 * @retval VIREO_RESULT_OVERFLOW
 *     双容量受检合计无法表示，状态保持。
 * @retval VIREO_RESULT_NOT_FOUND
 *     监听不存在或未绑定。
 * @retval VIREO_RESULT_IO
 *     单次MOD失败，旧配置/开关保持，无重试。
 * @retval VIREO_RESULT_INTERNAL
 *     本层容量账异常；其他依赖原分类返回。
 *
 * @note 全部校验后，仅READ变化才MOD，成功后发布；无运行期申请。
 * @note 启用时手动监听开关BUSY；成功unbind清策略，disable仅清配置、保留实际开关。
 * @note 策略容量只在消费release后退款，consume/send不退款；所有路径保持入口errno。
 */
vireo_result_t vireo_tcp_server_admission_configure(vireo_tcp_server_t *server,
    vireo_tcp_server_admission_options_t const *options, vireo_tcp_server_listener_error_t *error);

/**
 * @brief 按当前名额及固定双容量余量刷新监听READ
 *
 * @param[in,out] server
 *     非空存活且准入策略enabled的对象，Reactor-only。
 * @param[out] error
 *     可空独立监听原诊断。
 *
 * @retval VIREO_OK
 *     实际开关与当前推导一致，同值省MOD。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空，主要状态保持。
 * @retval VIREO_RESULT_BUSY
 *     同 server 任一业务/调度/自动服务在途，资源和主要输出保持。
 * @retval VIREO_RESULT_NOT_FOUND
 *     未启用或无绑定监听。
 * @retval VIREO_RESULT_IO
 *     一次MOD失败，旧实际开关保持，不回滚资源真账。
 * @retval VIREO_RESULT_INTERNAL
 *     资源账异常，其他依赖分类原样。
 *
 * @note 旧显式admit/release/run_once不隐式刷新；下一serve入口也执行刷新。
 * @note 没有高低水位滞回，不以实际buffer占用推导；无申请，所有路径保持errno。
 */
vireo_result_t vireo_tcp_server_admission_refresh(vireo_tcp_server_t *server,
    vireo_tcp_server_listener_error_t *error);

/**
 * @brief 停用自动准入策略而保留当前监听实际开关
 *
 * @param[in,out] server
 *     非空存活对象，无监听或未启用也允许重复停用。
 * @param[out] error
 *     可空独立诊断，成功语义零。
 *
 * @retval VIREO_OK
 *     配置语义零，不MOD/DEL/close；当前READ可能仍false。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空，主要状态保持。
 * @retval VIREO_RESULT_BUSY
 *     同 server 任一业务/调度/自动服务在途，资源和主要输出保持。
 *
 * @note Reactor-only，无运行期申请；停用后可用旧手动开关恢复READ。
 * @note 不更改已有客户flow、队列、owner或字节借用；所有路径保持errno。
 */
vireo_result_t vireo_tcp_server_admission_disable(vireo_tcp_server_t *server,
    vireo_tcp_server_listener_error_t *error);

/**
 * @brief 一次等待服务已有客户，再有限自动准入新客户并同步容量压力
 *
 * @param[in,out] server
 *     非空存活对象，自动准入enabled且有自有绑定监听，整次serving_active。
 * @param[in] options
 *     非空独立显式共同配置，入口复制；原客户容量/flow在其turn校验。
 * @param[in,out] wire_workspace
 *     非空独立原响应工作区，仅本调用短借用；共同拒绝保持。
 * @param[in] workspace_capacity
 *     至少process最大响应整帧，单位字节。
 * @param[in] handler
 *     非空原同步handler，有界非阻塞正常返回，不保留请求借用。
 * @param[in,out] context
 *     可空caller context，仅本次借用；独立server可嵌套。
 * @param[out] out_turns
 *     必需独立原逐客户结果数组，仅写本轮真实turn前缀。
 * @param[in] turn_capacity
 *     1..65535，与round客户上限/等待后Q取min。
 * @param[out] out_clients
 *     必需独立新客户租约数组，有效前缀min(max_accepts,capacity)入口全零。
 * @param[in] client_capacity
 *     1..65535，限制本轮新accept成功数。
 * @param[out] out_info
 *     必需独立组合统计，共同/pre-sync/wait拒绝保持，成功wait后提交真实进度。
 * @param[out] error
 *     可空独立主/补压力同步诊断，按值保留原round/client/监听原因。
 *
 * @retval VIREO_OK
 *     完成有限一轮，含没有新READ、原客户预算/EAGAIN/半帧、新接入额度/预算停止。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空，主要状态保持。
 * @retval VIREO_RESULT_BUSY
 *     同 server 任一业务/调度/自动服务在途，资源和主要输出保持。
 * @retval VIREO_RESULT_RANGE
 *     共同预算/帧/数组/新客户容量兼容拒绝；客户turn拒绝则提交真实前缀。
 * @retval VIREO_RESULT_NOT_FOUND
 *     策略未启用或监听未绑定；原客户拒绝则沿旧round报告。
 * @retval VIREO_RESULT_IO
 *     同步/wait/客户/接入失败，或本次listener ERROR/HANGUP；不猜事件errno。
 * @retval VIREO_RESULT_NO_MEMORY
 *     新客户构造申请失败，已有客户/先前新租约进度不回滚。
 * @retval VIREO_RESULT_PROTOCOL
 *     原客户帧/handler协议失败，跳过新准入，仍末尾同步。
 * @retval VIREO_RESULT_INTERNAL
 *     不变量或原依赖内部失败；其他依赖分类沿旧合同返回。
 *
 * @note 共同拒绝无任何系统操作；pre-sync失败不等待，wait失败保持主要输出/Q，但已提交READ不回滚。
 * @note 成功wait后先原FIFO服务，再仅本次READ有限接入，监听ERROR/HANGUP报IO且不accept/close。
 * @note 新lease在成功登记后属于server，flow初始化失败也必须输出，admitted与initialized分计；caller修复或release，不自动DEL/close。
 * @note 首客户错误跳过准入，首准入/初始化错误停接入；仍一次post-sync，主因/次错独立，不重试或回滚。
 * @note 新客户本轮不drive，下一轮就绪服务；默认READY不自动归还，开启模式时消费后才准入。
 *     归还首错跳过准入仍一次post-sync，主归还错与同步次错分开；旧显式入口不隐式刷新。
 * @note serving_active保护同server全部mutable/递归/destroy BUSY，观察允许；原三active定义保持，Reactor-only。
 * @note run期间公共serve_once递归BUSY；原共同/模式/容量拒绝后，已停止对象成功交付语义零统计，数组/workspace/Q保持。
 * @note 只原新connection构造申请资源；控制字段计统一预算。地址独立有效对齐不重叠，沿原读借用期限，保持errno。
 */
vireo_result_t vireo_tcp_server_serve_once(vireo_tcp_server_t *server,
    vireo_tcp_server_serve_options_t const *options, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_turn_result_t *out_turns, size_t turn_capacity,
    vireo_connection_pool_lease_t *out_clients, size_t client_capacity,
    vireo_tcp_server_serve_info_t *out_info, vireo_tcp_server_serve_error_t *error);

/** 连续运行入口复制四组数值；无待办时阻塞等待，不提供忙轮询timeout。 */
typedef struct vireo_tcp_server_run_options {
    vireo_tcp_server_process_options_t process; /**< 原共同帧上限，执行时须兼容准入配置。 */
    vireo_tcp_server_drive_budget_t drive; /**< 原每客户收/处理/发预算，分别计费。 */
    vireo_tcp_server_round_budget_t round; /**< 原单轮客户数量上限。 */
    vireo_tcp_server_admit_budget_t admit; /**< 原每轮accept成功数/系统次数上限。 */
} vireo_tcp_server_run_options_t;

/** 连续调用终止阶段；不重排已有有限轮次阶段。 */
typedef enum vireo_tcp_server_run_stage {
    VIREO_TCP_SERVER_RUN_NONE = 0, /**< 成功或共同参数/在途拒绝。 */
    VIREO_TCP_SERVER_RUN_STOP_SNAPSHOT = 1, /**< 公开loop停止观察异常，原分类返回。 */
    VIREO_TCP_SERVER_RUN_SERVE = 2 /**< 有限serve终止，完整原诊断保留。 */
} vireo_tcp_server_run_stage_t;

/** 只描述当前终止轮，之前的轮次已由回调交付，无无限累计。 */
typedef struct vireo_tcp_server_run_error {
    vireo_tcp_server_run_stage_t stage; /**< 未执行拒绝为NONE。 */
    bool round_available; /**< 当前serve是否已成功等待，才有真实统计/回调。 */
    vireo_tcp_server_serve_info_t round_info; /**< available时本轮真实前缀，其他时语义零。 */
    vireo_tcp_server_serve_error_t serve_error; /**< 包括主错误与补同步次错的完整原诊断。 */
} vireo_tcp_server_run_error_t;

/** 每次成功等待的服务轮结束后调用，包含执行失败；所有view仅借到返回。
 * turns有效前缀info.round.turn_count，clients有效前缀info.admission.admitted_count。
 * 同server原显式mutable允许，shutdown_batch、run/run_once/serve_once递归与destroy仍BUSY。
 * released=true的turn.client仅历史身份；仍owned客户需释放时复制lease到独立地址。
 * void回调的操作错误由context自行记录；模式开关在observer设置从下一轮生效。
 */
typedef void (*vireo_tcp_server_round_callback_t)(vireo_tcp_server_t *server,
    vireo_result_t result, vireo_tcp_server_serve_info_t const *info,
    vireo_tcp_server_turn_result_t const *turns,
    vireo_connection_pool_lease_t const *clients,
    vireo_tcp_server_serve_error_t const *error, void *context);

/**
 * @brief 持续执行有界服务轮，并在下一轮前观察永久停止意图
 *
 * @param[in,out] server
 *     非空存活对象，整次含回调running_active；Reactor-only。
 * @param[in] options
 *     非空独立四组数值，入口复制；正常执行须启用且绑定准入策略。
 * @param[in,out] wire_workspace
 *     独立原响应工作区，整次调用借用。
 * @param[in] workspace_capacity
 *     至少最大响应整帧，单位字节。
 * @param[in] handler
 *     原有界非阻塞同步handler，仅借用至run返回。
 * @param[in,out] context
 *     原handler context，可空，仅借用至run返回。
 * @param[out] out_turns
 *     独立固定逐客户数组，每轮仅写真实前缀。
 * @param[in] turn_capacity
 *     1..65535；与原round上限共同约束。
 * @param[in,out] out_clients
 *     独立新lease数组，初始有效前缀全零；不是owner。
 * @param[in] client_capacity
 *     1..65535，与admit.max_accepts取min。
 * @param[in] callback
 *     必需void逐轮回调，有界正常返回，不保留view指针。
 * @param[in,out] callback_context
 *     可空独立context，仅整次调用借用。
 * @param[out] error
 *     可空独立终止诊断，包含是否有当前轮及完整serve原因。
 *
 * @retval VIREO_OK
 *     已永久停止；合法已停止对象不等待/不回调，数组/workspace保持。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址/handler/callback为空、accept预算零或初始lease非空。
 * @retval VIREO_RESULT_RANGE
 *     原帧/预算/数组容量拒绝，入口拒绝保持主要数组/workspace。
 * @retval VIREO_RESULT_BUSY
 *     同server任一执行在途或run递归，资源保持。
 * @return
 *     首有限执行错误原分类；先交付成功wait的真实轮，再返回，不被同时stop改写。
 *
 * @note 无待办timeout=-1，有待办原FIFO强制0；无运行期数组申请或累计计数。
 * @note 每个成功wait后（含客户/准入/末同步错误）回调，pre-sync/wait拒绝没有伪造轮。
 * @note 回调可原释放/策略/字节/关闭/安排缓存/request_stop，原四active均已结束；shutdown_batch仍BUSY，独立server可嵌套。
 * @note 下轮仅清此前admitted的lease副本以复用；caller须在回调返回前复制仍需使用的信息。
 * @note 回调停用策略/解绑或改不兼容配置会使下一轮按旧合同拒绝，除非先请求stop。
 * @note 当前整轮含准入、末同步及回调完成后才停止；不自动重试/回滚或选择关闭理由。
 *     READY归还仅依显式auto_release_ready模式，已释放turn租约仅历史身份。
 * @note run返回不代表客户或全部停止请求者结束，所有输入地址独立有效不重叠，保持入口errno。
 */
vireo_result_t vireo_tcp_server_run(vireo_tcp_server_t *server,
    vireo_tcp_server_run_options_t const *options, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_turn_result_t *out_turns, size_t turn_capacity,
    vireo_connection_pool_lease_t *out_clients, size_t client_capacity,
    vireo_tcp_server_round_callback_t callback, void *callback_context,
    vireo_tcp_server_run_error_t *error);

/**
 * @brief 透传自有loop的线程安全永久停止与单次非阻塞通知
 *
 * @param[in] server
 *     非空已通过外部同步发布的存活对象；借到本次返回。
 * @param[out] error
 *     可空独立loop原诊断，多个请求者各用自己的输出。
 *
 * @retval VIREO_OK
 *     意图已提交，单次通知成功或EAGAIN；重复允许。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     server为空。
 * @return
 *     其他公开loop原分类及完整诊断；IO不撤停止意图，可再次请求补通知。
 *
 * @note 仅此server入口可跨线程，不读取Reactor客户/在途状态；无新atomic/pipe/reset。
 * @note 不支持信号处理器调用；不自动重试，不解除客户所有权，保持入口errno。
 * @note caller须保证server/loop/不可变依赖context活到所有运行者和请求者结束后再destroy。
 */
vireo_result_t vireo_tcp_server_request_stop(vireo_tcp_server_t *server,
    vireo_event_loop_error_t *error);

/** 停止后的槽检查预算；空槽也计费，不提供无界全表清理。 */
typedef struct vireo_tcp_server_shutdown_budget {
    size_t max_slots; /**< 正 1..MAX_CONNECTIONS，每批实际至多检查容量一圈。 */
} vireo_tcp_server_shutdown_budget_t;

/** 清理批次停止原因；错误优先，否则依次检查客户空、槽预算、结果容量。 */
typedef enum vireo_tcp_server_shutdown_stop {
    VIREO_TCP_SERVER_SHUTDOWN_COMPLETE = 0, /**< 客户已空，server 其他资源仍存活。 */
    VIREO_TCP_SERVER_SHUTDOWN_SLOT_BUDGET = 1, /**< 本批允许检查的槽位已用尽。 */
    VIREO_TCP_SERVER_SHUTDOWN_RESULT_CAPACITY = 2, /**< 输出已满，不再探查下一槽。 */
    VIREO_TCP_SERVER_SHUTDOWN_ERROR = 3 /**< 首客户释放失败，包含该客户真实结果。 */
} vireo_tcp_server_shutdown_stop_t;

/** 一次存活客户的释放事实；lease 是原身份副本，不是资源 owner。 */
typedef struct vireo_tcp_server_shutdown_result {
    vireo_connection_pool_lease_t lease; /**< 释放前身份；released 后旧副本失效。 */
    vireo_result_t result; /**< 原释放分类，消费型 IO 仍返回 IO。 */
    bool released; /**< 客户是否实际消费；不能仅凭 result 推断。 */
    vireo_tcp_server_client_error_t error; /**< 完整原诊断，不拥有客户资源。 */
} vireo_tcp_server_shutdown_result_t;

/** 本批有限进度与当前剩余所有权快照，不累计以前批次。 */
typedef struct vireo_tcp_server_shutdown_info {
    size_t scanned_slots; /**< 已检查槽数，含空槽和失败客户槽。 */
    size_t attempted_clients; /**< 本批尝试数，也是结果数组有效前缀长度。 */
    size_t released_clients; /**< 实际消费数，包含消费型关闭 IO。 */
    size_t remaining_clients; /**< server 当前仍拥有的客户数。 */
    size_t next_slot; /**< 本批结束游标，失败客户也已越过。 */
    vireo_tcp_server_shutdown_stop_t stop_reason; /**< 本批实际停止边界。 */
} vireo_tcp_server_shutdown_info_t;

/**
 * @brief 在永久停止后，按槽预算注销并归还客户，放弃其读写数据
 *
 * @param[in,out] server
 *     非空存活资源根；Reactor-only，所有运行者及停止请求者须已结束。
 * @param[in] budget
 *     非空独立正 max_slots，范围 1..MAX_CONNECTIONS。
 * @param[out] out_results
 *     非空独立固定数组，仅写 attempted_clients 前缀；其他元素保持。
 * @param[in] result_capacity
 *     正 1..MAX_CONNECTIONS，不要求入口元素为空。
 * @param[out] out_info
 *     必需独立真实进度；前置拒绝保持全部语义成员。
 * @param[out] error
 *     可空独立首错误诊断，成功或前置拒绝语义零。
 *
 * @retval VIREO_OK
 *     客户空、槽预算或结果容量停止；须读 remaining_clients 判断是否清空。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空、槽预算或结果容量为零，主要输出保持。
 * @retval VIREO_RESULT_RANGE
 *     槽预算或结果容量超过硬限，主要输出保持。
 * @retval VIREO_RESULT_BUSY
 *     未永久停止，或同 server 任一执行、run、清理在途，主要输出保持。
 * @return
 *     首客户释放错误原分类，提交包含失败客户的真实前缀及完整原诊断。
 *
 * @note 至多检查 min(max_slots,connection_capacity) 个槽，从持久游标轮转；
 *     每槽本次至多一次，空槽也计预算，结果满后不继续扫描。失败也推进游标，
 *     后续是否再调用由 caller 决定；没有自动重试或回滚。
 * @note 每客户严格一次 DEL 后归还；DEL 失败保绑定/资源/队列/额度，归还拒绝
 *     保持客户及已解绑状态。关闭 IO 仍消费、撤队退款，released=true；不重试 close。
 * @note caller 须结束全部客户字节/body/其他借用；消费后旧借用和 lease 立即失效。
 *     外部借用及请求者结束不能自行验证，不支持并发销毁、signal handler 或异步取消。
 * @note 整批 shutdown_active 保护普通可变入口/递归/destroy BUSY，观察及独立 server
 *     允许；原 request_stop 跨线程合同保持。run 的逐轮回调期间也不能调用本入口。
 * @note 不 receive/send/process/handler，不自动 request_close、drain 或释放服务轮 READY。
 *     想保留待发数据须先 drain；收尾批次之间 caller 不应再准入或使用待释放客户。
 * @note 无运行期申请，listener/loop/pool/control 保留；客户空后须显式旧 destroy。
 *     未停止或在途拒绝先于扫描，停止快照异常保持主要输出并标 INSPECT_SERVER；
 *     没有强制绕过 DEL 失败的整体 loop 销毁出口。
 * @note 全部地址须独立有效、对齐且不重叠，所有路径保持入口 errno。
 */
vireo_result_t vireo_tcp_server_shutdown_batch(vireo_tcp_server_t *server,
    vireo_tcp_server_shutdown_budget_t const *budget,
    vireo_tcp_server_shutdown_result_t *out_results, size_t result_capacity,
    vireo_tcp_server_shutdown_info_t *out_info, vireo_tcp_server_client_error_t *error);


/**
 * @brief 设置服务轮成功READY客户的自动归还模式，默认关闭
 *
 * @param[in,out] server
 *     非空存活对象，Reactor-only；只改变模式，不扫描、排队或立即释放客户。
 * @param[in] enabled
 *     true启用；同值重复成功，逐轮observer可设置并从下一轮生效。
 * @param[out] error
 *     可空独立client诊断，成功/参数拒绝/BUSY为语义零。
 *
 * @retval VIREO_OK
 *     已保存模式，入口errno保持。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     server为空。
 * @retval VIREO_RESULT_BUSY
 *     同server处理/驱动/调度/服务/清理在途，模式保持。
 *
 * @note 仅run_once/serve_once/run中drive成功且ready_to_release的已服务客户，
 *     在驱动和loop回调返回后一次DEL→pool release，消费后才继续客户/准入。
 *     原客户预算/结果容量约束尝试次数，不全池扫描或新申请。
 * @note turn的result/info/error与成功/失败计数仍只描述drive；独立release字段/计数
 *     描述归还，首释放错停轮。DEL错保资源，归还拒绝保已解绑状态；消费型close IO
 *     仍released=true且退款，turn.client仅历史身份，不能再使用。
 * @note 调用可能消费客户的轮前须结束全部外部客户借用。drive失败不自动释放；显式
 *     byte/process/drive及shutdown_batch不受本模式影响，不自动选关闭理由或drain。
 *     已停止单轮仍零业务，不清理；仅request_stop允许跨线程。
 */
vireo_result_t vireo_tcp_server_set_auto_release_ready(vireo_tcp_server_t *server,
    bool enabled, vireo_tcp_server_client_error_t *error);


/**
 * @brief 设置服务轮的EOF与真实网络错误关闭策略，默认关闭
 *
 * @param[in,out] server
 *     非空存活对象，Reactor-only；只保存模式，不扫描、立即关闭或安排客户。
 * @param[in] enabled
 *     true启用固定窄规则；同值OK，observer可设置且下一轮生效。
 * @param[out] error
 *     可空独立client诊断，成功/参数拒绝/BUSY语义零。
 *
 * @retval VIREO_OK
 *     模式已保存，不改变auto_release_ready或已有永久关闭意图。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     server为空。
 * @retval VIREO_RESULT_BUSY
 *     同server处理/驱动/调度/服务/清理在途，模式保持。
 *
 * @note 仅run_once/serve_once/run在drive和loop/handler回调返回后使用。
 *     成功OPEN且已recv EOF、读区空才DRAIN/PEER_EOF；缓存未空继续旧有界处理。
 *     原请求frames_peek的PROTOCOL选择IMMEDIATE/PROTOCOL；实际recv/send的IO
 *     （原errno非EINTR）选择IMMEDIATE/IO，DRAINING可升级且首次理由保持。
 * @note handler、响应编码、MOD/inspect/参数/租约错误及通知ERROR/HANGUP不猜坏连接；
 *     EINTR仍原IO，不自动重试。策略请求至多一次，MOD IO不撤已提交意图/首理由。
 *     IMMEDIATE放弃未发响应，DRAIN无时间保证，关闭开关停用不恢复OPEN。
 * @note 原turn.result/info/error及成功/失败计数只计drive；独立close字段报告策略。
 *     drive原错优先，策略次错另存；失败客户不自动回队或释放。drive成功而策略错
 *     为ROUND_CLOSE，caller观察真实意图再决定恢复；serve仍一次末尾监听同步。
 * @note 成功EOF新READY只尾插一次，下轮沿原成功drive READY门槛可选归还；
 *     DRAINING等WRITE，不重写原drive hint。关闭/归还模式独立，不全池扫描或新申请。
 *     显式byte/process/drive及shutdown_batch不读取本模式，停后单轮仍零业务。
 * @note 所有路径保持入口errno和原借用期限，参数/诊断独立存活对齐不重叠。
 *     仅request_stop可跨线程；整体停机、deadline和错误回复不由本接口提供。
 */
vireo_result_t vireo_tcp_server_set_auto_close_policy(vireo_tcp_server_t *server,
    bool enabled, vireo_tcp_server_client_error_t *error);


/** 关闭请求扫描预算，空槽也计费。 */
typedef struct vireo_tcp_server_close_batch_budget {
    size_t max_slots; /**< 正1..MAX_CONNECTIONS，每批实际至多一圈。 */
} vireo_tcp_server_close_batch_budget_t;

/** 本批停止边界；不表示所有客户已排空或已释放。 */
typedef enum vireo_tcp_server_close_batch_stop {
    VIREO_TCP_SERVER_CLOSE_BATCH_EMPTY = 0, /**< 当前无客户，其他资源仍存活。 */
    VIREO_TCP_SERVER_CLOSE_BATCH_SCAN_LIMIT = 1, /**< 槽预算或本池一圈已用尽。 */
    VIREO_TCP_SERVER_CLOSE_BATCH_RESULT_CAPACITY = 2, /**< 结果满，不再探查下一槽。 */
    VIREO_TCP_SERVER_CLOSE_BATCH_ERROR = 3 /**< 首客户lookup/关闭/安排失败。 */
} vireo_tcp_server_close_batch_stop_t;

/** 独立组合阶段，不重排旧client/round等枚举。 */
typedef enum vireo_tcp_server_close_batch_stage {
    VIREO_TCP_SERVER_CLOSE_BATCH_NONE = 0,
    VIREO_TCP_SERVER_CLOSE_BATCH_SNAPSHOT = 1, /**< 公开停止或本层不变量检查失败。 */
    VIREO_TCP_SERVER_CLOSE_BATCH_LOOKUP = 2,
    VIREO_TCP_SERVER_CLOSE_BATCH_REQUEST = 3,
    VIREO_TCP_SERVER_CLOSE_BATCH_QUEUE = 4
} vireo_tcp_server_close_batch_stage_t;

/** 按值阶段事实，不拥有客户或读写借用。 */
typedef struct vireo_tcp_server_close_batch_result {
    vireo_connection_pool_lease_t lease; /**< 操作时的身份，后续消费可使其失效。 */
    vireo_result_t result; /**< 本行首结果，不代表连接释放。 */
    bool close_attempted; /**< 是否实际调用一次公开request_close。 */
    vireo_result_t close_result; /**< lookup或请求结果，未请求也可为错误。 */
    vireo_tcp_server_client_error_t close_error; /**< 原lookup/请求完整诊断。 */
    bool schedule_attempted; /**< 仅关闭成功后尝试确保旧FIFO位置。 */
    vireo_result_t schedule_result; /**< 未尝试为OK，错误不回滚关闭。 */
    bool scheduled; /**< 位置确保成功，含原已有位置，不代表新尾插。 */
} vireo_tcp_server_close_batch_result_t;

/** 本批真实进度；计数均受原槽/数组上限约束，不累计跨批。 */
typedef struct vireo_tcp_server_close_batch_info {
    size_t scanned_slots; /**< 含空槽和失败槽。 */
    size_t processed_clients; /**< 结果数组有效前缀，含失败客户。 */
    size_t close_attempted_clients; /**< 实际request_close尝试数。 */
    size_t scheduled_clients; /**< 确保位置数，含去重成功。 */
    size_t owned_clients; /**< 当前客户所有权数，本批不消费或退款。 */
    size_t next_slot; /**< 下一批扫描起点，失败也前进。 */
    vireo_tcp_server_close_batch_stop_t stop_reason;
} vireo_tcp_server_close_batch_info_t;

/** 首阶段原因；QUEUE无虚构系统errno，关闭原诊断仍在对应结果行。 */
typedef struct vireo_tcp_server_close_batch_error {
    vireo_tcp_server_close_batch_stage_t stage;
    vireo_connection_pool_lease_t client;
    vireo_tcp_server_client_error_t client_error;
} vireo_tcp_server_close_batch_error_t;

/**
 * @brief 有界扫描owned客户，提交关闭意图并确保后续服务轮机会
 *
 * @param[in,out] server
 *     非空存活对象，Reactor-only；running observer可调用。
 * @param[in] mode
 *     DRAIN或IMMEDIATE；理由固定SERVER_STOP，首次理由保持。
 * @param[in] budget
 *     必需独立正max_slots，范围1..MAX_CONNECTIONS。
 * @param[out] out_results
 *     必需独立数组，只写processed_clients前缀，其余元素保持。
 * @param[in] result_capacity
 *     正1..MAX_CONNECTIONS，限制本批live客户结果数。
 * @param[out] out_info
 *     必需独立进度；前置拒绝保持，开始扫描后提交真实前缀。
 * @param[out] error
 *     可空独立首因；成功与参数/在途/已停止拒绝语义零。
 *
 * @retval VIREO_OK
 *     当前空或扫描/数组上限停止，不保证全池已关闭、排空或释放。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址/正值缺失或mode非法，主要输出保持。
 * @retval VIREO_RESULT_RANGE
 *     槽预算或结果容量超过硬限，主要输出保持。
 * @retval VIREO_RESULT_BUSY
 *     已永久停止或同server业务/调度/服务/关闭/清理在途，输出保持。
 * @return
 *     首lookup/关闭/队列原分类；提交含失败行的真实进度，不重试或回滚。
 *
 * @note 至多min(max_slots,capacity)槽，每槽本批一次，空槽计费，结果满后不探查。
 *     独立游标失败也前进；批间是当前成员，没有跨批固定快照或完整停服保证。
 * @note 关闭成功才确保旧FIFO；已有位置不移位、不重复。MOD错误可已有永久意图，
 *     QUEUE错误不撤关闭；失败不自动安排，caller据真实状态决定恢复或释放。
 * @note DRAIN只排空已有写队列。caller先停准入、处理希望保留的read缓存；本批不
 *     receive/process/send、DEL/释放/stop或加期限，关闭和归还模式仍独立。
 * @note closing_active保护全部普通mutable/递归/destroy，观察和独立server允许；
 *     原request_stop唯一跨线程且不读新普通状态，批中stop不抢占当前有限批。
 * @note 本批不消费owner/固定额度或结束读借用；后续可能归还的轮前须结束借用。
 *     已停止沿旧shutdown_batch，destroy仍须所有运行者/请求者结束与客户空。
 * @note 无运行期申请；所有地址独立有效对齐不重叠，所有路径保持入口errno。
 */
vireo_result_t vireo_tcp_server_close_batch(vireo_tcp_server_t *server,
    vireo_connection_close_mode_t mode, vireo_tcp_server_close_batch_budget_t const *budget,
    vireo_tcp_server_close_batch_result_t *out_results, size_t result_capacity,
    vireo_tcp_server_close_batch_info_t *out_info, vireo_tcp_server_close_batch_error_t *error);

#endif /* VIREO_NET_TCP_SERVER_H */
