/*
- PROJECT : VIREO
- FILE    : tls_connection.h
- AUTHOR  : bitofux
- DATE    : 2026-10-17
- BRIEF   : 此模块负责：
- -- 服务器逐连接TLS资源、非阻塞握手步进及状态观测
- -- 借用socket且不接管关闭责任；提供有界应用数据收发与有期限双向TLS关闭
 */
#ifndef VIREO_NET_TLS_CONNECTION_H
#define VIREO_NET_TLS_CONNECTION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <vireo/base/clock.h>
#include <vireo/base/buffer.h>
#include <vireo/base/result.h>
#include <vireo/net/tls_context.h>

/** 本层控制块预算硬限；不包含OpenSSL内部申请或内核socket资源。 */
#define VIREO_TLS_CONNECTION_MAX_WRAPPER_BYTES ((size_t)67108864)

/** 唯一owner；不可复制，无公开native指针、fd操作句柄或布局。 */
typedef struct vireo_tls_connection vireo_tls_connection_t;

/** 本层握手生命周期；完成/失败均永久，不支持重置或重新握手。 */
typedef enum vireo_tls_handshake_state {
    VIREO_TLS_HANDSHAKE_INITIAL = 0,     /**< 尚未尝试原生握手调用。 */
    VIREO_TLS_HANDSHAKE_HANDSHAKING = 1, /**< 至少尝试一次，等待指定方向后继续。 */
    VIREO_TLS_HANDSHAKE_ESTABLISHED = 2, /**< 本端真实握手完成，不等于账号认证。 */
    VIREO_TLS_HANDSHAKE_FAILED = 3       /**< 首个致命失败已保存，禁止继续网络I/O。 */
} vireo_tls_handshake_state_t;

/** 最近一步需要的单一方向，非位掩码；调用者据此安排等待。 */
typedef enum vireo_tls_handshake_wait {
    VIREO_TLS_HANDSHAKE_WAIT_NONE = 0,  /**< 初态或终态，无握手等待方向。 */
    VIREO_TLS_HANDSHAKE_WAIT_READ = 1,  /**< 等待可读后再调用同一握手入口。 */
    VIREO_TLS_HANDSHAKE_WAIT_WRITE = 2  /**< 等待可写后再调用同一握手入口。 */
} vireo_tls_handshake_wait_t;

/** 独立单步报告；原生致命失败及期限到期均提交，原生前参数/状态拒绝则保持。 */
typedef struct vireo_tls_handshake_info {
    vireo_tls_handshake_state_t state; /**< 本次返回时的四态之一。 */
    vireo_tls_handshake_wait_t wait;   /**< 最新等待方向，不累积历史方向。 */
    bool native_called;               /**< 本次是否真正执行过一次原生握手。 */
} vireo_tls_handshake_info_t;

/** 期限历史的独立值快照；不采时、不保活对象，也不表示此刻是否到期。 */
typedef struct vireo_tls_handshake_deadline_info {
    bool armed;                       /**< 一次装载锁存；禁用不用时间数值哨兵。 */
    vireo_monotonic_ns_t deadline_ns;   /**< 同域有限绝对期限；未装载为0，装载后不续期。 */
    vireo_monotonic_ns_t last_now_ns;   /**< 装载或最近已提交驱动的now；未装载为0。 */
} vireo_tls_handshake_deadline_info_t;

/** 显式包装预算；成功后固定，不提供增长或第三方总内存承诺。 */
typedef struct vireo_tls_connection_options {
    size_t max_wrapper_bytes; /**< 正字节数，足够控制块且不超过64MiB。 */
} vireo_tls_connection_options_t;

/** 独立配置快照，不保活对象或fd，不证明握手/对端身份。 */
typedef struct vireo_tls_connection_info {
    uint16_t minimum_protocol_version; /**< 实际最低版本，固定TLS1.3。 */
    uint16_t maximum_protocol_version; /**< 实际最高版本，固定TLS1.3。 */
    bool server_mode;                 /**< 实际服务器角色，固定true。 */
    bool handshake_started;           /**< 本层已尝试至少一次原生握手，含无字节WANT。 */
    bool handshake_complete;          /**< 本层曾确认native握手完成；应用fatal不抹历史，不等于账号认证。 */
    bool fd_bound;                    /**< 双向BIO绑定原fd数值，不证明外部fd仍有效。 */
    size_t wrapper_bytes;             /**< 本层控制块实际申请字节，非稳定ABI。 */
    size_t max_wrapper_bytes;         /**< 创建时提供的包装预算。 */
    vireo_tls_handshake_state_t handshake_state; /**< 本层完整握手生命周期。 */
    vireo_tls_handshake_wait_t handshake_wait;   /**< 最近一次正常未完成的方向。 */
} vireo_tls_connection_info_t;

/** 失败阶段只描述本次操作；与线协议状态和SSL_get_error分类无关。 */
typedef enum vireo_tls_connection_stage {
    VIREO_TLS_CONNECTION_STAGE_NONE = 0,             /**< 成功或基本参数/预算拒绝。 */
    VIREO_TLS_CONNECTION_STAGE_VALIDATE_FD = 1,      /**< socket只读资格查询/形态拒绝。 */
    VIREO_TLS_CONNECTION_STAGE_VALIDATE_CONTEXT = 2, /**< context配置不满足前置合同。 */
    VIREO_TLS_CONNECTION_STAGE_ALLOCATE_WRAPPER = 3, /**< 本层控制块申请失败。 */
    VIREO_TLS_CONNECTION_STAGE_CREATE_NATIVE = 4,    /**< SSL资源创建失败。 */
    VIREO_TLS_CONNECTION_STAGE_BIND_FD = 5,          /**< 不关闭fd的BIO创建失败。 */
    VIREO_TLS_CONNECTION_STAGE_INSPECT = 6,          /**< 逐连接配置或本层不变量异常。 */
    VIREO_TLS_CONNECTION_STAGE_HANDSHAKE = 7,        /**< 原生握手致命失败。 */
    VIREO_TLS_CONNECTION_STAGE_SIGNAL_POLICY = 8,    /**< SIGPIPE策略不符或查询失败。 */
    VIREO_TLS_CONNECTION_STAGE_CONFIGURE_IO = 9, /**< 固定应用缓冲配置/资源失败。 */
    VIREO_TLS_CONNECTION_STAGE_RECEIVE = 10, /**< 应用读取致命失败。 */
    VIREO_TLS_CONNECTION_STAGE_SEND = 11, /**< 应用写入致命失败。 */
    VIREO_TLS_CONNECTION_STAGE_DEADLINE = 12, /**< 握手入口观察到固定期限已到。 */
    VIREO_TLS_CONNECTION_STAGE_CLOSE = 13, /**< 原生关闭致命失败。 */
    VIREO_TLS_CONNECTION_STAGE_CLOSE_DEADLINE = 14 /**< 关闭总期限到达，零原生调用。 */
} vireo_tls_connection_stage_t;

/** caller拥有的本次独立诊断，不含材料文本或库错误字符串借用。 */
typedef struct vireo_tls_connection_error {
    vireo_tls_connection_stage_t stage; /**< 当前失败阶段；成功/基本拒绝为NONE。 */
    int system_errno;                  /**< 查询/握手SYSCALL原errno（允许0），其余0。 */
    uint64_t openssl_error_code;        /**< 本次首个库原因码，无原因则0。 */
    bool has_more_errors;              /**< 本次还消费了其他库原因码。 */
} vireo_tls_connection_error_t;

/**
 * @brief 创建借用socket的服务器TLS对象，配置完整后才发布唯一owner
 *
 * @param[in] context
 *     非空存活服务器context，仅借到返回；与其访问/销毁串行。
 *     成功后SSL持库内native引用，不保存包装地址，原包装随后可销毁。
 * @param[in] options
 *     非空稳定选项，max_wrapper_bytes为正且足够本层控制块、不超过硬限。
 * @param[in] borrowed_fd
 *     >=0（0合法）的已连接SOCK_STREAM，已设O_NONBLOCK和FD_CLOEXEC。
 *     全生命周期借用，唯一拥有者保证未关闭/复用；不与其他TLS/明文I/O混用。
 * @param[in,out] out_connection
 *     独立必需owner地址，入口值NULL；成功后用destroy配对释放。
 * @param[out] error
 *     可空独立诊断；每条可写路径覆盖逻辑字段，不影响实际清理。
 *
 * @retval VIREO_OK
 *     完整发布TLS1.3服务器待握手对象，未收发任何网络字节。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空、非空owner、负fd、零预算，或查询成功但socket形态/flags不符。
 * @retval VIREO_RESULT_RANGE
 *     正预算不足本层控制块或超过硬限。
 * @retval VIREO_RESULT_IO
 *     F_GETFL/F_GETFD/SO_TYPE/getpeername查询失败；诊断保存原errno，不重试。
 * @retval VIREO_RESULT_NO_MEMORY
 *     本层申请失败或捕获到明确OpenSSL malloc failure。
 * @retval VIREO_RESULT_INTERNAL
 *     context/逐连接不变量异常或无法可靠细分的库资源失败。
 *
 * @note 失败保持主owner全部字节；逆序释放实际所得资源，不部分发布或自动重试。
 *     成功/失败都不close、dup或改变fd flags，不转移fd所有权。
 * @note 所有入口保持errno。基本参数/预算拒绝不触OpenSSL错误队列；通过该前置后
 *     清当前线程旧队列，执行查询及库操作，失败立即保存本次原因，清理后队列空。
 *     caller预先保存自己的旧库错误；系统与库原因分列，不猜造错误或打印诊断。
 * @note 预算只含本层控制块，不含SSL/BIO/SSL_CTX引用/provider/allocator/RSS、
 *     内核资源或调用耗时；不承诺总TLS内存或硬实时。
 * @note 同对象caller/Reactor串行；不支持并发访问/销毁、强制取消、signal handler
 *     或fork后未exec调用。worker不取得TLS对象/fd；本项不修改epoll。
 * @note 所有地址存活、对齐、按声明可读写、独立不重叠，不在自有资源内，不指errno。
 *     NULL检查不能验证野地址或长期fd身份；不冻结padding/私有sizeof/ABI。
 * @note 此创建入口只建立服务器初态，不握手、收发、shutdown或发送close_notify。
 *     现有raw connection收发接入TLS仍需后续公共transport合同。
 */
vireo_result_t vireo_tls_connection_create_server(vireo_tls_context_t const *context,
    vireo_tls_connection_options_t const *options, int borrowed_fd,
    vireo_tls_connection_t **out_connection, vireo_tls_connection_error_t *error);

/**
 * @brief 观测真实逐连接配置及完整握手生命周期，成功后发布独立快照
 *
 * @param[in] connection
 *     非空存活TLS对象，caller串行短借到返回。
 * @param[out] out_info
 *     必需独立输出，失败保持全部字节；成功快照不延长对象/fd寿命。
 * @param[out] error
 *     可空独立本次诊断，成功/参数拒绝为NONE/0/0/false。
 *
 * @retval VIREO_OK
 *     native配置与本层生命周期不变量满足合同，快照完整发布；应用fatal后握手完成仍为历史true。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空，不触库队列且保持主输出。
 * @retval VIREO_RESULT_INTERNAL
 *     native或本层状态异常，阶段为INSPECT，主输出保持。
 *
 * @note 保持errno；合法操作清当前线程旧库队列，返回时队列空。
 *     不查询内核fd、不分配本层资源，不证明外部fd存活/身份或对端信任。
 * @note 地址/线程/生命周期要求沿创建合同，无握手或网络动作。
 */
vireo_result_t vireo_tls_connection_inspect(vireo_tls_connection_t const *connection,
    vireo_tls_connection_info_t *out_info, vireo_tls_connection_error_t *error);

/**
 * @brief 最多执行一次非阻塞服务器握手，提交等待、完成或致命失败报告
 *
 * @param[in,out] connection
 *     必需存活对象，caller/Reactor串行短借；原context包装允许已销毁。
 *     借用fd身份/非阻塞属性稳定，不与其他SSL/明文I/O或并发close混用。
 * @param[out] out_info
 *     必需独立报告。原生前拒绝保持全部字节；真正调用后即使失败也完整提交。
 *     终态重复亦提交，native_called=false，不执行新握手。
 * @param[out] error
 *     可空独立诊断；成功/WANT/基本参数拒绝为NONE/0/0/false。
 *
 * @retval VIREO_OK
 *     握手完成或正常WANT_READ/WRITE；调用者必须读取state/wait区分。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空或真正握手前SIGPIPE disposition不是SIG_IGN。
 * @retval VIREO_RESULT_IO
 *     只读信号查询失败，或原生SSL_ERROR_SYSCALL；原原因保存于system_errno。
 * @retval VIREO_RESULT_PROTOCOL
 *     TLS层致命失败或完成前对端协议关闭；不保证错误必由畸形远端造成。
 * @retval VIREO_RESULT_NO_MEMORY
 *     原生SSL_ERROR_SSL对应本次队列含明确malloc failure。
 * @retval VIREO_RESULT_BUSY
 *     已装载期限且握手未终结，须改用handshake_step_at；主报告保持。
 * @retval VIREO_RESULT_TIMEOUT
 *     重复已缓存的期限失败，不查询时间/信号或执行网络，仍提交终态报告。
 * @retval VIREO_RESULT_INTERNAL
 *     本层/native不变量异常、不可能返回组合或不支持的其他WANT机制。
 *
 * @note INITIAL/HANDSHAKING每次最多一次SSL_do_handshake；不循环、等待或自动重试。
 *     一次库调用可能内部多次读写/密码计算/申请，不承诺字节、RSS或耗时硬限。
 *     等待后复用同一对象、以最新wait续调度；不修改epoll。未arm时没有隐式期限。
 * @note 应用须在启动期明确将SIGPIPE设为SIG_IGN并保持策略稳定；每次真正握手前
 *     本层只读查询并拒绝不符。仅屏蔽线程信号不满足前置；本库不改disposition、
 *     mask或pending。终态重复无网络调用，不要求再次查询信号。
 * @note 保持入口errno；基本参数拒绝保留旧库队列，其余合法路径清旧队列并返回空队列。
 *     原生调用前errno=0，返回后即时保存，失败时同线程紧邻SSL_get_error、无中间库调用，
 *     再独立保存首码/多码事实。caller预先保存自己的旧错误，不以返回时errno取原因。
 * @note 致命失败永久FAILED且缓存首result/诊断；重复返回同首错并报告零原生调用。
 *     网络进度不回滚、不自动销毁/close/shutdown；caller结束访问后先TLS销毁再关闭fd。
 *     ESTABLISHED重复成功，不重新握手；应用失败由独立io_inspect报告；无客户端身份验证。
 * @note 地址/owner/串行及调用上下文限制沿资源合同，不支持signal handler、强制取消
 *     或fork后未exec。诊断/报告与对象、彼此及errno独立不重叠，不保存输出地址。
 */
vireo_result_t vireo_tls_connection_handshake_step(vireo_tls_connection_t *connection,
    vireo_tls_handshake_info_t *out_info, vireo_tls_connection_error_t *error);

/**
 * @brief 在首次原生握手前一次装载固定总期限，不执行握手或采集系统时间
 *
 * @param[in,out] connection
 *     必需存活、INITIAL且未装载期限的串行TLS对象，沿创建的owner/fd合同。
 * @param[in] now
 *     caller本次成功采集的同域CLOCK_MONOTONIC纳秒时间点，按值保存为last_now_ns。
 * @param[in] deadline
 *     caller选定起点受检计算的同域有限绝对时间点；0/MAX均合法，允许<=now。
 * @param[out] error
 *     可空独立诊断，成功/基本拒绝为NONE/0/0/false，不保存输出地址。
 *
 * @retval VIREO_OK
 *     三个期限字段一次发布；即使已过期也先装载，TIMEOUT由step_at统一提交。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     connection为NULL，不触旧库队列。
 * @retval VIREO_RESULT_BUSY
 *     已装载或非INITIAL，原期限及握手全部保持，不能续期/解除/重置。
 * @retval VIREO_RESULT_INTERNAL
 *     本层/native不变量异常，诊断INSPECT，原对象保持。
 *
 * @note 无本层分配、网络、信号查询或clock读取；不相加时间值、不注册timer。
 *     沿资源串行/独立地址/生命周期合同，保持errno；基本拒绝外清旧队列并返回空队列。
 *     caller负责时间来源、受检计算及到期唤醒；此API不能证明两个数属于同一时间域。
 */
vireo_result_t vireo_tls_connection_handshake_deadline_arm(vireo_tls_connection_t *connection,
    vireo_monotonic_ns_t now, vireo_monotonic_ns_t deadline, vireo_tls_connection_error_t *error);

/**
 * @brief 用显式入口时间检查固定期限，未到期才至多执行一次原生握手
 *
 * @param[in,out] connection
 *     必需存活串行对象，未终态时须已arm；fd/SSL/SIGPIPE前置沿handshake_step。
 * @param[in] now
 *     caller紧邻本次驱动采集的同域单调时间；活跃握手不得小于last_now_ns，相等允许。
 *     终态完全不使用该值。时钟采样失败不得拿旧now冒本次采样成功。
 * @param[out] out_info
 *     必需独立主报告。TIMEOUT即使原生未调用也提交FAILED/NONE/false；原生后及
 *     终态重复沿旧step提交；其他原生前拒绝保持全部字节及last_now_ns。
 * @param[out] error
 *     可空独立诊断；TIMEOUT为DEADLINE/0/0/false，重复首错保持原原因。
 *
 * @retval VIREO_OK
 *     已完成或正常WANT，须读报告区分；真实原生发生才提交本轮last_now_ns。
 * @retval VIREO_RESULT_TIMEOUT
 *     未终态且now>=deadline，永久缓存失败并提交now；或重复同一超时首错。
 * @retval VIREO_RESULT_BUSY
 *     未终态且未装载期限，无原生/信号查询，报告及对象保持。
 * @retval VIREO_RESULT_RANGE
 *     活跃握手now回退，报告及对象保持，可修正时间后再驱动。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空，或未到期且SIGPIPE策略不符；地址拒绝保留旧库队列。
 * @retval VIREO_RESULT_IO
 *     未到期的信号查询失败、原生SYSCALL，或重复已缓存原生IO首错。
 * @retval VIREO_RESULT_PROTOCOL
 *     原生协议失败或重复同首错，沿旧step分类。
 * @retval VIREO_RESULT_NO_MEMORY
 *     原生明确OOM或重复同首错，沿旧step分类。
 * @retval VIREO_RESULT_INTERNAL
 *     本层/native异常、原生不可能组合或重复同首错，沿旧step分类。
 *
 * @note 先验证不变量/处理终态，再检查期限。到期零原生/信号查询，不发送警报或
 *     close_notify，不close fd；先TLS销毁再由fd owner关闭。超时对象不可恢复。
 *     期限固定，WANT/少量进展不续期；不在原生返回后再采时，入口未到期的一次
 *     原生调用即使跨过期限仍提交原生结果，不提供抢占、CPU或墙钟硬实时保证。
 * @note caller负责无fd事件时也按期限唤醒再驱动；本层不等待、不接epoll/timer。
 *     保持errno、队列清理/紧邻错误分类及地址/串行/寿命边界沿旧step，无新增资源。
 */
vireo_result_t vireo_tls_connection_handshake_step_at(vireo_tls_connection_t *connection,
    vireo_monotonic_ns_t now, vireo_tls_handshake_info_t *out_info,
    vireo_tls_connection_error_t *error);

/**
 * @brief 观测已装载期限和最近已提交时间，不采时或推进握手
 *
 * @param[in] connection 必需存活串行对象，INITIAL/等待/终态均可观察。
 * @param[out] out_info 必需独立快照，成功才完整发布，任何失败保持全部字节。
 * @param[out] error 可空独立诊断，成功/地址拒绝为NONE/0/0/false。
 * @retval VIREO_OK 发布三个值，未arm为false/0/0；不因真实时间流逝而改变状态。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需地址为空，旧库队列保持。
 * @retval VIREO_RESULT_INTERNAL 本层/native不变量异常，诊断INSPECT，主输出保持。
 * @note 无分配/网络/信号查询/系统采时；快照不保活对象，时间是历史值。
 *     保持errno；通过地址前置后清旧队列并返回空队列；其他要求沿创建的串行/寿命合同。
 */
vireo_result_t vireo_tls_connection_handshake_deadline_inspect(vireo_tls_connection_t const *connection,
    vireo_tls_handshake_deadline_info_t *out_info, vireo_tls_connection_error_t *error);

/**
 * @brief 结束全部使用后释放TLS资源并清空owner，结束socket借用
 *
 * @param[in,out] connection
 *     必需独立owner地址；非空值须为未消费的唯一对象，空值允许重复成功。
 * @param[out] error
 *     可空独立诊断，成功/地址拒绝均为NONE/0/0/false。
 *
 * @retval VIREO_OK
 *     SSL/BIO/本层控制块已释放且owner为NULL，或本来为空。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     owner地址为NULL。
 *
 * @note 不close/dup/shutdown fd，不发送close_notify、不等待peer；caller随后由唯一
 *     拥有者关闭socket。原context包装允许已销毁，native引用由SSL内部配对释放。
 * @note 先结束全部访问/借用；旧别名失效，不提供自动并发寿命检测。
 *     保持errno，非空销毁清线程库队列，空owner成功不触队列；释放无失败返回。
 */
vireo_result_t vireo_tls_connection_destroy(vireo_tls_connection_t **connection,
    vireo_tls_connection_error_t *error);

/** 两个独立暂存各16KiB；容量预算含全部四个字节分配，不含控制块/库/RSS。 */
#define VIREO_TLS_IO_SCRATCH_BYTES ((size_t)16384)
#define VIREO_TLS_IO_MAX_BUFFER_BYTES ((size_t)67108864)

/** 应用状态与握手历史独立；FAILED永久，已有明文仍可peek/consume；不按数值大小判就绪。 */
typedef enum vireo_tls_io_state {
    VIREO_TLS_IO_DISABLED = 0, /**< 未配置，所有I/O资源为空。 */
    VIREO_TLS_IO_OPEN = 1, /**< 已配置；关闭请求后网络许可还须看close状态。 */
    VIREO_TLS_IO_FAILED = 2, /**< 永久首错，禁止后续网络。 */
    VIREO_TLS_IO_PREPARED = 3 /**< 四资源固定已分配，业务禁用；真实握手成功后原地启用OPEN。 */
} vireo_tls_io_state_t;

/** 应用原操作最新需要的网络方向；与旧握手等待类型分开，非位掩码。 */
typedef enum vireo_tls_io_wait {
    VIREO_TLS_IO_WAIT_NONE = 0, /**< 无网络等待或本次被另一操作优先。 */
    VIREO_TLS_IO_WAIT_READ = 1, /**< 等网络可读后继续同一原操作。 */
    VIREO_TLS_IO_WAIT_WRITE = 2 /**< 等网络可写后继续同一原操作。 */
} vireo_tls_io_wait_t;

/** 当前优先继续的原操作，与READ/WRITE网络等待方向不同。 */
typedef enum vireo_tls_io_operation {
    VIREO_TLS_IO_OPERATION_NONE = 0, /**< 无独占优先重试。 */
    VIREO_TLS_IO_OPERATION_READ = 1, /**< 先继续receive原请求。 */
    VIREO_TLS_IO_OPERATION_WRITE = 2, /**< 先继续send原请求。 */
    VIREO_TLS_IO_OPERATION_SHUTDOWN = 3 /**< 继续关闭通知；只在close快照出现。 */
} vireo_tls_io_operation_t;

/** OK的停止原因也必须读取；一次停止不表示业务消息完成。 */
typedef enum vireo_tls_io_stop {
    VIREO_TLS_IO_STOP_WOULD_BLOCK = 0, /**< 原生WANT，等最新wait后续同一原操作。 */
    VIREO_TLS_IO_STOP_PEER_EOF = 1, /**< 已真实读取close_notify，接收方向结束。 */
    VIREO_TLS_IO_STOP_BUFFER_FULL = 2, /**< 固定读FIFO已满，须先consume。 */
    VIREO_TLS_IO_STOP_BUFFER_EMPTY = 3, /**< 无待发字节，暂不需要send。 */
    VIREO_TLS_IO_STOP_BYTE_BUDGET = 4, /**< 本轮确认明文达到字节预算。 */
    VIREO_TLS_IO_STOP_CALL_BUDGET = 5, /**< 本轮原生调用达到次数预算。 */
    VIREO_TLS_IO_STOP_RETRY_OTHER = 6, /**< 另一原操作有独占优先，当前零调用。 */
    VIREO_TLS_IO_STOP_ERROR = 7, /**< 本轮发生错误或返回永久首错。 */
    VIREO_TLS_IO_STOP_FLOW_PAUSED = 8 /**< 最近refresh锁住压力，暂停新应用读取。 */
} vireo_tls_io_stop_t;

/** prepare/configure短借并值复制；两路径互斥，容量固定，不隐式增长或热重配。 */
typedef struct vireo_tls_io_options {
    size_t read_capacity; /**< 正字节数，固定明文读FIFO容量。 */
    size_t write_capacity; /**< 正字节数，固定待发FIFO容量。 */
    size_t max_buffer_bytes; /**< read+write+32768<=此预算<=64MiB，先检查溢出。 */
    size_t max_read_unit_bytes; /**< 完整保留才消费的最大明文单元，1..read_capacity。 */
    size_t read_low; /**< unit-1<=low<high<=read_capacity，防半帧水位死锁。 */
    size_t read_high; /**< 达到即锁住读压力。 */
    size_t write_low; /**< 0<=low<high<=write_capacity。 */
    size_t write_high; /**< 达到即锁住写压力；不禁止排空。 */
} vireo_tls_io_options_t;

/** 两个正数；限制确认明文与SSL_ex调用次数，不是syscalls/耗时/密文限制。 */
typedef struct vireo_tls_io_budget {
    size_t max_bytes; /**< 已有WANT重试须至少原request长度，否则RANGE。 */
    size_t max_native_calls; /**< 包括WANT、EOF及fatal的原生调用。 */
} vireo_tls_io_budget_t;

/** 原生前拒绝保持整个输出；调用后fatal仍发布此前已确认前缀。 */
typedef struct vireo_tls_io_progress {
    size_t bytes; /**< 本轮确认的明文字节，未确认write不消费。 */
    size_t native_calls; /**< 本轮实际SSL_read_ex/write_ex次数。 */
    vireo_tls_io_stop_t stop_reason; /**< 唯一停止原因。 */
    vireo_tls_io_wait_t wait; /**< 最新网络等待方向，非原操作。 */
} vireo_tls_io_progress_t;

/** 独立快照，不含地址/owner，不保活对象；DISABLED也可观测。 */
typedef struct vireo_tls_io_info {
    vireo_tls_io_state_t state; /**< 独立应用生命周期。 */
    bool read_eof; /**< 已确认对端close_notify；关闭请求前仍允许反向发送。 */
    vireo_tls_io_options_t options; /**< 成功prepare/configure的八选项，DISABLED全零。 */
    size_t buffer_bytes; /**< 两FIFO容量和两暂存请求之和。 */
    size_t read_size; /**< 已解密且未消费明文。 */
    size_t write_size; /**< 尚未确认的FIFO字节。 */
    size_t read_retry_bytes; /**< 锁定的read请求长度，0表示无。 */
    size_t write_retry_bytes; /**< 锁定的write请求长度，0表示无。 */
    vireo_tls_io_wait_t read_wait; /**< 最近read WANT方向。 */
    vireo_tls_io_wait_t write_wait; /**< 最近write WANT方向。 */
    vireo_buffer_info_t read_buffer; /**< 原读FIFO真实容量/占用/尾空；DISABLED全零。 */
    vireo_buffer_info_t write_buffer; /**< 原写FIFO真实快照；尾空不含已消费头洞。 */
} vireo_tls_io_info_t;

/** refresh才更新迟滞；纯建议，不修改epoll、不执行网络/分配。 */
typedef struct vireo_tls_io_flow {
    bool read_pressure; /**< >=high锁、<=low解，中间保持。 */
    bool write_pressure; /**< 同上，只限制新应用读，不禁止send。 */
    bool application_read_enabled; /**< 无压力/EOF/fatal/独占retry时允许新应用读。 */
    bool want_read; /**< 需要网络READ；写重试也可能需要。 */
    bool want_write; /**< 需要网络WRITE；读重试也可能需要。 */
    bool resume_read; /**< 库内明文或预算停止，可安排一次有界本地续读。 */
    bool resume_write; /**< 写预算停止，可安排一次有界本地续写。 */
    vireo_tls_io_operation_t priority_retry; /**< 先续原write，再独占read-WANT_WRITE。 */
} vireo_tls_io_flow_t;

/**
 * @brief 首次握手前一次性准备固定应用资源，成功只发布PREPARED
 *
 * @param[in,out] connection
 *     必需存活串行对象，须INITIAL且尚未原生握手、I/O DISABLED；允许已经arm期限。
 * @param[in] options
 *     必需独立稳定八项配置，成功值复制，不保存地址；容量/水位边界沿io_configure。
 * @param[out] error
 *     可空独立诊断；资源失败沿CONFIGURE_IO，不从errno猜原因。
 *
 * @retval VIREO_OK
 *     两FIFO和两个16KiB暂存完整发布，PREPARED空队列/零retry/EOF/压力/续调度。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需指针为空。
 * @retval VIREO_RESULT_OVERFLOW
 *     两容量加32768不可表示。
 * @retval VIREO_RESULT_RANGE
 *     正容量/unit、水位或read+write+32768<=max_buffer_bytes<=64MiB不成立。
 * @retval VIREO_RESULT_BUSY
 *     已尝试握手、非INITIAL或已经prepare/configure；不支持热重配。
 * @retval VIREO_RESULT_NO_MEMORY
 *     固定资源不足，或原生策略失败有明确malloc原因。
 * @retval VIREO_RESULT_INTERNAL
 *     原生配置不符合策略。
 *
 * @note 失败逆序释放候选，原I/O资源/选项/状态及握手/期限保持；不承诺SSL逐字节回滚。
 *     无网络/握手/loop注册/fd属性变化，不采时/续期；分配不承诺硬实时。
 * @note PREPARED可inspect真实容量；peek/consume/enqueue/receive/send均BUSY（含零字节），
 *     主输出保持；flow_refresh全零且不查SSL_pending。握手失败也不开放应用。
 *     原handshake_step/step_at确认成功并完成校验后同次返回前激活OPEN，四资源地址不变，
 *     不再为四字节区分配；WANT/超时/fatal不激活，失败资源保留至destroy。
 * @note 原io_configure仍仅握手后DISABLED可用，两路径互斥；prepare不能补在HANDSHAKING。
 *     容量预算不含控制块/第三方/内核/RSS；连接池仍只计两FIFO，不含32768暂存。
 * @note Reactor-only，所有对象/输出独立不重叠，借用有效期沿create；保持errno。
 *     基本指针/数值/算术拒绝保持OpenSSL队列，其余清空，不修改共享SSL_CTX或信号策略。
 */
vireo_result_t vireo_tls_connection_io_prepare(vireo_tls_connection_t *connection,
    vireo_tls_io_options_t const *options, vireo_tls_connection_error_t *error);

/**
 * @brief 握手完成后一次性建立固定应用缓冲，失败全部回滚
 *
 * @param[in,out] connection
 *     存活串行对象；须ESTABLISHED且I/O DISABLED。
 * @param[in] options
 *     非空稳定配置，地址独立，成功值复制。
 * @param[out] error
 *     可空独立诊断，资源失败阶段CONFIGURE_IO。
 *
 * @retval VIREO_OK
 *     全部资源发布OPEN，AUTO_RETRY开、read_ahead=0，partial/moving/ignoreEOF关。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需指针为空。
 * @retval VIREO_RESULT_OVERFLOW
 *     两容量加32768不可表示。
 * @retval VIREO_RESULT_RANGE
 *     零数值、水位关系不合规或超容量/预算硬限。
 * @retval VIREO_RESULT_BUSY
 *     未完成握手或已prepare/configure。
 * @retval VIREO_RESULT_NO_MEMORY
 *     缓冲或暂存资源不足。
 * @retval VIREO_RESULT_INTERNAL
 *     原生配置异常。
 *
 * @note 无网络、共享SSL_CTX不变。保持errno；基本参数/算术拒绝保留库队列，其余清空。
 *     四个字节分配固定，buffer控制块/OpenSSL/内核不计入容量预算。沿创建的串行/地址合同。
 */
vireo_result_t vireo_tls_connection_io_configure(vireo_tls_connection_t *connection,
    vireo_tls_io_options_t const *options, vireo_tls_connection_error_t *error);

/**
 * @brief 有界解密到固定读FIFO，WANT锁定自有暂存原参数
 *
 * @param[in,out] connection
 *     存活串行已配置对象；fd/SIGPIPE合同沿handshake_step。
 * @param[in] budget
 *     非空两个正数，已有重试须给足原长度。
 * @param[out] out_progress
 *     独立必需报告，原生前拒绝保持；原生后错误也发布实际前缀。
 * @param[out] error
 *     可空独立诊断；fatal缓存首错，不改握手历史。
 *
 * @retval VIREO_OK
 *     正常进度/WANT/EOF/预算/容量/另一操作优先，须读取报告。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空或信号策略不符。
 * @retval VIREO_RESULT_RANGE
 *     零预算或重试预算不足，报告保持。
 * @retval VIREO_RESULT_BUSY
 *     I/O未配置或已请求关闭，主报告保持。
 * @retval VIREO_RESULT_IO
 *     信号查询失败或SSL_ERROR_SYSCALL，保存即时errno。
 * @retval VIREO_RESULT_TIMEOUT
 *     关闭已永久超时，主报告保持并返回关闭首诊断。
 * @retval VIREO_RESULT_PROTOCOL
 *     TLS错误、裸EOF；仅read ZERO_RETURN是正常EOF。
 * @retval VIREO_RESULT_NO_MEMORY
 *     SSL错误队列明确malloc failure。
 * @retval VIREO_RESULT_INTERNAL
 *     不支持WANT/不可能结果/本层不变量异常。
 *
 * @note 每次原生前查询SIG_IGN；errno=0→原生→保存errno→紧邻SSL_get_error→消费队列。
 *     保持入口errno；基本参数/预算拒绝保留旧队列，其余清空。信号拒绝不缓存，可恢复；
 *     若前面已有原生调用则仍发布已发生进度。fatal永久禁网络，重复报告ERROR/0/0/NONE。
 *     每个新请求min(剩余字节预算,16384,空位)；locked请求不改地址/长度。
 *     任意write WANT使receive报告RETRY_OTHER；read WANT_READ允许send，WANT_WRITE禁止。
 *     关闭FAILED返回其缓存首错（含TIMEOUT）且主报告保持；其他关闭态BUSY。
 *     合法receive结束旧read view（含零进度），consume/destroy亦然；不隐式握手/等待。
 */
vireo_result_t vireo_tls_connection_receive(vireo_tls_connection_t *connection,
    vireo_tls_io_budget_t const *budget, vireo_tls_io_progress_t *out_progress,
    vireo_tls_connection_error_t *error);

/**
 * @brief 借用完整连续只读明文，空态NULL/0，EOF/FAILED仍可读
 *
 * @param[in] connection
 *     非空存活已配置串行对象。
 * @param[out] out_data
 *     必需独立只读借用输出，不得修改/释放/直接enqueue到本对象。
 * @param[out] out_size
 *     必需独立长度输出，与其他地址不重叠。
 * @param[out] error
 *     可空独立诊断。
 *
 * @retval VIREO_OK
 *     同时发布两个输出；失败二者整个保持。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空。
 * @retval VIREO_RESULT_BUSY
 *     DISABLED/PREPARED，主要输出保持，即使握手已经失败也不返回业务view。
 *
 * @note view到下次合法receive、通过模式/时间/locked预算前置的非终态close_step_at、
 *     成功consume（含0）或destroy；send/enqueue/inspect/flow不终止。
 *     保持errno，合法路径清库队列，无网络/分配；串行/地址限制沿create。
 */
vireo_result_t vireo_tls_connection_read_peek(vireo_tls_connection_t const *connection,
    uint8_t const **out_data, size_t *out_size, vireo_tls_connection_error_t *error);

/**
 * @brief 消费已处理明文前缀，EOF/FAILED允许
 *
 * @param[in,out] connection
 *     非空存活已配置串行对象。
 * @param[in] size
 *     0..read_size，成功含0终止旧view。
 * @param[out] error
 *     可空独立诊断。
 *
 * @retval VIREO_OK
 *     完整消费，不分配/缩容。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     对象为空。
 * @retval VIREO_RESULT_BUSY
 *     DISABLED/PREPARED（含零消费），不访问FIFO。
 * @retval VIREO_RESULT_RANGE
 *     超当前可读长度，全部保持。
 *
 * @note 保持errno，基本参数拒绝保留库队列，其余清空；无网络。
 */
vireo_result_t vireo_tls_connection_read_consume(vireo_tls_connection_t *connection,
    size_t size, vireo_tls_connection_error_t *error);

/**
 * @brief 完整复制入待发FIFO，容量不足完整拒绝；允许为复用头洞而compact
 *
 * @param[in,out] connection
 *     非空存活已配置串行对象。
 * @param[in] data
 *     短借源，size>0必需非空且可读size字节；不得重叠任一本对象自有资源。
 * @param[in] size
 *     字节数，0允许NULL；超限检查先于读取源。
 * @param[out] error
 *     可空独立诊断。
 *
 * @retval VIREO_OK
 *     完整复制，源借用到返回结束，WANT中亦可追加。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空。
 * @retval VIREO_RESULT_BUSY
 *     DISABLED/PREPARED或已请求关闭（包括零字节入队）。
 * @retval VIREO_RESULT_OVERFLOW
 *     size加已有队列不可表示。
 * @retval VIREO_RESULT_RANGE
 *     超固定容量。
 * @retval VIREO_RESULT_IO
 *     应用FAILED且缓存首错为IO。
 * @retval VIREO_RESULT_PROTOCOL
 *     应用FAILED且缓存首错为PROTOCOL。
 * @retval VIREO_RESULT_NO_MEMORY
 *     应用FAILED且缓存首错为NO_MEMORY。
 * @retval VIREO_RESULT_INTERNAL
 *     应用FAILED且缓存首错为INTERNAL。
 *
 * @retval VIREO_RESULT_TIMEOUT
 *     关闭已永久超时，返回关闭首诊断。
 * @note close FAILED优先返回缓存关闭首错；其他失败不改原FIFO或read view。
 * @note 保持errno；基本参数拒绝保留库队列，其余清空。无网络/增长/隐式水位刷新。
 */
vireo_result_t vireo_tls_connection_enqueue(vireo_tls_connection_t *connection,
    uint8_t const *data, size_t size, vireo_tls_connection_error_t *error);

/**
 * @brief 有界发送稳定前缀快照，完整原生成功才消费同长FIFO
 *
 * @param[in,out] connection
 *     存活已配置串行对象，借用fd/SIGPIPE合同沿receive。
 * @param[in] budget
 *     两个正数；锁定重试须至少原长度。
 * @param[out] out_progress
 *     必需独立报告；发布/保持规则沿receive。
 * @param[out] error
 *     可空独立诊断，stage SEND；首fatal永久缓存。
 *
 * @retval VIREO_OK
 *     正常进度/WANT/预算/空队列/另一操作优先；读取报告区分。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空，或SIGPIPE不是SIG_IGN。
 * @retval VIREO_RESULT_RANGE
 *     零预算或当前字节预算不足原locked请求，报告保持。
 * @retval VIREO_RESULT_BUSY
 *     应用I/O为DISABLED/PREPARED或已请求关闭，主报告保持，不执行握手。
 * @retval VIREO_RESULT_IO
 *     信号查询失败或原生SYSCALL，独立保存原errno。
 * @retval VIREO_RESULT_TIMEOUT
 *     关闭已永久超时，主报告保持并返回关闭首诊断。
 * @retval VIREO_RESULT_PROTOCOL
 *     原生SSL致命错误或write ZERO_RETURN。
 * @retval VIREO_RESULT_NO_MEMORY
 *     原生SSL错误队列含明确malloc failure。
 * @retval VIREO_RESULT_INTERNAL
 *     不支持的WANT、不可能原生结果或本层不变量异常。
 *
 * @note WANT期间同地址/内容/长度，enqueue/compact不影响独立快照；禁partial/moving模式。
 *     读WANT_WRITE时报告RETRY_OTHER；读WANT_READ可穿插send。EOF允许反向写。
 *     FIFO消费仅指库确认，不证明对端业务提交；无SSL_shutdown/close/epoll修改。
 *     关闭FAILED返回其缓存首错（含TIMEOUT）且主报告保持；其他关闭态BUSY。
 *     errno/队列/逐原生信号检查与失败恢复沿receive，send不终止read view。
 */
vireo_result_t vireo_tls_connection_send(vireo_tls_connection_t *connection,
    vireo_tls_io_budget_t const *budget, vireo_tls_io_progress_t *out_progress,
    vireo_tls_connection_error_t *error);

/**
 * @brief 复制独立应用I/O快照，DISABLED/PREPARED也合法
 *
 * @param[in] connection
 *     非空存活串行对象。
 * @param[out] out_info
 *     必需独立输出，失败整个保持。
 * @param[out] error
 *     可空独立诊断。
 *
 * @retval VIREO_OK
 *     发布容量/占用/独立状态/EOF/重试长度和方向。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空。
 *
 * @note 无网络/分配，不证明fd身份；保持errno，合法调用清库队列，不结束read view。
 */
vireo_result_t vireo_tls_connection_io_inspect(vireo_tls_connection_t const *connection,
    vireo_tls_io_info_t *out_info, vireo_tls_connection_error_t *error);

/**
 * @brief 显式刷新迟滞与调度建议，不执行网络、epoll或分配
 *
 * @param[in,out] connection
 *     非空存活串行对象，仅修改两个水位锁存。
 * @param[out] out_flow
 *     必需独立输出，失败保持整个输出。
 * @param[out] error
 *     可空独立诊断。
 *
 * @retval VIREO_OK
 *     发布建议；DISABLED/PREPARED全零且不查SSL_pending，FAILED无网络或续调度建议。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空。
 *
 * @retval VIREO_RESULT_BUSY
 *     已请求关闭，保持输出及锁存，改用close_inspect的调度建议。
 * @note write WANT优先，其次read WANT_WRITE；方向只取优先retry的最新WANT。
 *     压力不能屏蔽write需要的协议READ。SSL_pending或预算停止可有界本地续调度；
 *     SSL_has_pending本身不触发立即重试。实际WANT清除对应预算续调度标记，避免空转。
 *     字节操作不隐式刷新水位。保持errno，合法调用清库队列；read view保持。
 */
vireo_result_t vireo_tls_connection_flow_refresh(vireo_tls_connection_t *connection,
    vireo_tls_io_flow_t *out_flow, vireo_tls_connection_error_t *error);

/** 关闭生命周期与握手/I/O历史独立；终态不可恢复，不代表fd已关闭。 */
typedef enum vireo_tls_close_state {
    VIREO_TLS_CLOSE_NONE = 0, /**< 未request，普通收发可用。 */
    VIREO_TLS_CLOSE_DRAINING = 1, /**< 完成原重试并排空既有写队列。 */
    VIREO_TLS_CLOSE_NOTIFYING = 2, /**< 正在发送本端通知，可能WANT。 */
    VIREO_TLS_CLOSE_WAIT_PEER = 3, /**< 本端通知成功，用read接尾部/对端通知。 */
    VIREO_TLS_CLOSE_COMPLETE = 4, /**< 双向通知完成，读FIFO仍可能非空。 */
    VIREO_TLS_CLOSE_FAILED = 5 /**< 首错永久，禁止继续网络。 */
} vireo_tls_close_state_t;

/** 本轮停止原因；下一操作/等待由info说明，可能已切换操作。 */
typedef enum vireo_tls_close_stop {
    VIREO_TLS_CLOSE_STOP_PROGRESS = 0, /**< 一次读/写/本端通知进展。 */
    VIREO_TLS_CLOSE_STOP_WANT = 1, /**< 原生需等待；看info选择下一操作。 */
    VIREO_TLS_CLOSE_STOP_NEED_CONSUME = 2, /**< 固定读空间不足，先消费。 */
    VIREO_TLS_CLOSE_STOP_COMPLETE = 3, /**< 双向通知完成。 */
    VIREO_TLS_CLOSE_STOP_ERROR = 4 /**< 本次超时/fatal或返回旧首错。 */
} vireo_tls_close_stop_t;

/** 独立按值快照，不采时、不更新迟滞、不保活对象；NONE其余全零。 */
typedef struct vireo_tls_close_info {
    vireo_tls_close_state_t state; /**< 本层关闭阶段。 */
    vireo_monotonic_ns_t deadline_ns; /**< 一次固定总期限，含排空/通知/收尾。 */
    vireo_monotonic_ns_t last_now_ns; /**< request或最近提交step的时间。 */
    bool local_notify_sent; /**< 仅shutdown返回0/1确认，非仅SENT位。 */
    bool peer_notify_received; /**< 已处理对端通知，不代表业务已消费明文。 */
    vireo_tls_io_operation_t operation; /**< 下一操作；非网络等待方向。 */
    vireo_tls_io_wait_t wait; /**< 下一操作的真实WANT，非历史累积。 */
    bool resume; /**< 可安排一次有界本地续调度；单独has_pending不触发。 */
    bool needs_consume; /**< 下一个read原请求空间不足；不覆盖优先write所需READ。 */
} vireo_tls_close_info_t;

/** 参数/模式/回退/locked预算/原生前信号拒绝保持整个主输出。 */
typedef struct vireo_tls_close_progress {
    size_t read_bytes; /**< 本轮确认入读FIFO的明文。 */
    size_t write_bytes; /**< 本轮确认并消费写FIFO的明文。 */
    bool native_called; /**< 本轮是否调用一个SSL读/写/shutdown。 */
    vireo_tls_close_stop_t stop_reason; /**< 本轮停止原因。 */
    vireo_tls_close_info_t info; /**< 提交后的状态与下一步建议。 */
} vireo_tls_close_progress_t;

/**
 * @brief 一次封新入队并装载不可续期的关闭总期限，不执行网络
 *
 * @param[in,out] connection
 *     必需存活串行owner；握手ESTABLISHED、I/O OPEN、close NONE。
 * @param[in] now
 *     caller提供的同域单调纳秒时间，按值复制。
 * @param[in] deadline
 *     同域有限绝对期限，0/MAX及已过期合法，不可延长/解除。
 * @param[out] error
 *     可空独立诊断，失败不半装载或封口。
 *
 * @retval VIREO_OK
 *     成功request；旧enqueue/send/receive/flow从此门禁，改用close驱动。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     对象为空，旧库队列保持。
 * @retval VIREO_RESULT_BUSY
 *     未完成握手、未配置或已request。
 * @retval VIREO_RESULT_IO
 *     原I/O已FAILED，返回原首错，无shutdown。
 * @retval VIREO_RESULT_PROTOCOL
 *     原I/O协议首错。
 * @retval VIREO_RESULT_NO_MEMORY
 *     原I/O资源首错。
 * @retval VIREO_RESULT_INTERNAL
 *     原I/O内部首错。
 *
 * @note 无分配/采时/信号查询；保持errno，通过基本前置后清库队列。沿create串行/地址合同。
 *     业务若还需生成响应应推迟request；本入口不终止read view，不改变fd/context所有权。
 */
vireo_result_t vireo_tls_connection_close_request(vireo_tls_connection_t *connection,
    vireo_monotonic_ns_t now, vireo_monotonic_ns_t deadline, vireo_tls_connection_error_t *error);

/**
 * @brief 有期限地推进关闭，每次最多一个原生调用，完整保留未消费明文
 *
 * @param[in,out] connection
 *     必需存活串行已request对象；fd/SIGPIPE合同沿receive。
 * @param[in] now
 *     同域新采样时间；活跃回退拒绝，相等到期；终态不使用。
 * @param[in] max_bytes
 *     正预算；所选原read/write重试须给足原长度，不缩短请求。
 * @param[out] out_progress
 *     必需独立报告；原生fatal/到期也发布，前置拒绝保持全部字节。
 * @param[out] error
 *     可空独立诊断；读写fatal沿原stage，shutdown为CLOSE，超时CLOSE_DEADLINE。
 *
 * @retval VIREO_OK
 *     进展/WANT/需消费/完成；必须读取报告，不等待网络或业务消费。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空或实际原生前SIGPIPE非SIG_IGN。
 * @retval VIREO_RESULT_RANGE
 *     零预算、活跃时间回退或所选重试预算不足。
 * @retval VIREO_RESULT_BUSY
 *     未request，不执行隐式握手/配置。
 * @retval VIREO_RESULT_TIMEOUT
 *     总期限到达，零原生/信号查询，永久首错。
 * @retval VIREO_RESULT_IO
 *     原生SYSCALL或可恢复的信号查询失败，保存即时errno。
 * @retval VIREO_RESULT_PROTOCOL
 *     TLS致命/裸EOF错误，关闭永久失败。
 * @retval VIREO_RESULT_NO_MEMORY
 *     明确原生malloc failure，关闭永久失败。
 * @retval VIREO_RESULT_INTERNAL
 *     不支持WANT/不可能返回，或信号查询异常。
 *
 * @note 终态幂等、零原生/字节，首错优先于晚到期限；参数和正预算仍先验证。
 *     先写重试、read WANT_WRITE、排空写、发通知，后read到EOF；read WANT_READ可穿插发送。
 *     shutdown返回0正常，不调用get_error；负值保存errno后紧邻分类；fatal后不再shutdown。
 *     通过模式/时间/locked预算前置的非终态调用结束旧read view，之后重新peek。
 * @note 关闭读绕过普通水位，仍受固定空间/重试原长度限制；不丢尾部明文。
 *     COMPLETE不等于read FIFO空、fd关闭或业务提交。peek/consume/历史inspect继续可用。
 *     caller负责采时、到期唤醒/消费和最终TLS→fd清理；入口门禁不提供抢占/硬实时。
 *     保持errno；基本/零预算拒绝保留旧库队列，其余清理；无新分配/epoll/fd修改。
 */
vireo_result_t vireo_tls_connection_close_step_at(vireo_tls_connection_t *connection,
    vireo_monotonic_ns_t now, size_t max_bytes, vireo_tls_close_progress_t *out_progress,
    vireo_tls_connection_error_t *error);

/**
 * @brief 复制关闭历史和当前调度建议，不推进协议或时间
 *
 * @param[in] connection
 *     必需存活串行对象，NONE/终态也可观察。
 * @param[out] out_info
 *     必需独立输出，失败保持整个对象；成功复制值，不保活owner。
 * @param[out] error
 *     可空独立诊断。
 *
 * @retval VIREO_OK
 *     发布状态/时间/通知标记/下一操作/等待/本地续调度/消费需要。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空，旧库队列保持。
 *
 * @note 终态无操作/等待/续调度；NONE其余全零。SSL_pending可提示读，has_pending单独不触发。
 *     不采时/分配/网络/信号查询/刷新迟滞，保持read view/errno，合法路径清库队列。
 *     沿create的地址、所有权、寿命和Reactor串行合同。
 */
vireo_result_t vireo_tls_connection_close_inspect(vireo_tls_connection_t const *connection,
    vireo_tls_close_info_t *out_info, vireo_tls_connection_error_t *error);

/**
 * 应用暂存生命周期：Vireo自有read/write scratch在确认完成/读EOF后清零对应整块，
 * 应用fatal、关闭COMPLETE/FAILED及释放前清零两块。WANT和可恢复前置拒绝保持pending暂存；
 * 关闭终态仍保留未消费FIFO供caller处理，终态retry数值只作历史快照，不能继续native。
 * FIFO消费/整理/释放沿buffer清理合同；caller输入/workspace与OpenSSL/内核内部副本另负责任。
 * 清理保持errno，增加线性写零成本，不提供锁页或崩溃后全秘密清理保证。
 */

#endif
