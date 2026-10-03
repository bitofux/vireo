/*
- PROJECT : VIREO
- FILE    : connection.h
- AUTHOR  : bitofux
- DATE    : 2026-10-03
- BRIEF   : 此模块负责：
- -- 单个已连接非阻塞 stream socket 的唯一所有权
- -- 两个固定容量 buffer 的生命周期、受检字节预算与按值观察
- -- 有界非阻塞接收、EOF、只读借用与前缀消费
- -- 有界完整帧识别、基础校验、CRC 与只读批次
- -- 固定写队列的完整追加、有界发送与确认前缀消费
- -- 单 loop 绑定、显式关注和在途生命周期保护
- -- 帧流读写迟滞水位与显式关注同步
- -- 永久关闭意图、已有队列排空及上层安全释放协作
 */
#ifndef VIREO_NET_CONNECTION_H
#define VIREO_NET_CONNECTION_H

#include <stddef.h>
#include <stdbool.h>
#include <vireo/base/buffer.h>
#include <vireo/base/result.h>
#include <vireo/protocol/codec.h>
#include <vireo/net/event_loop.h>

/** 两字节区合计硬限；不含控制块、allocator/RSS、内核或多连接全局开销。 */
#define VIREO_CONNECTION_MAX_BUFFER_BYTES ((size_t)67108864)

/** 唯一拥有型对象；不公开布局或 sizeof，不可复制；所有入口仅 Reactor 线程使用。 */
typedef struct vireo_connection vireo_connection_t;

/** 三项均显式提供；成功创建后固定，不提供增长或 buffer 句柄。 */
typedef struct vireo_connection_options {
    size_t read_capacity;    /**< 正容量，<= VIREO_BUFFER_MAX_CAPACITY。 */
    size_t write_capacity;   /**< 正容量，<= VIREO_BUFFER_MAX_CAPACITY。 */
    size_t max_buffer_bytes; /**< 正预算，<= 本模块硬限，包含两字节区容量之和。 */
} vireo_connection_options_t;

/** 显式帧流策略；长度均为字节，最大帧包含 32 字节头，无默认值。 */
typedef struct vireo_connection_flow_options {
    size_t max_frame_bytes; /**< 32..min(读容量, 协议最大整帧)。 */
    size_t read_low;        /**< >= max_frame_bytes-1，且严格小于 read_high。 */
    size_t read_high;       /**< <= 读容量；占用达到此值锁读压力。 */
    size_t write_low;       /**< 可为 0，严格小于 write_high；降到此值解除写压力。 */
    size_t write_high;      /**< <= 写容量；占用达到此值锁写压力，暂停接收。 */
} vireo_connection_flow_options_t;

/** READY 是逻辑阶段，不证明已注销、回调结束或 fd 关闭。 */
typedef enum vireo_connection_close_state {
    VIREO_CONNECTION_CLOSE_OPEN = 0,
    VIREO_CONNECTION_CLOSE_DRAINING = 1,
    VIREO_CONNECTION_CLOSE_READY = 2
} vireo_connection_close_state_t;

/** NONE 仅用于初始观察；输入只接受 DRAIN/IMMEDIATE，不能逆向或 reset。 */
typedef enum vireo_connection_close_mode {
    VIREO_CONNECTION_CLOSE_MODE_NONE = 0,
    VIREO_CONNECTION_CLOSE_MODE_DRAIN = 1,
    VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE = 2
} vireo_connection_close_mode_t;

/** 首次原因由上层选择，永久保留；不会自动从 EOF/IO 推断。 */
typedef enum vireo_connection_close_reason {
    VIREO_CONNECTION_CLOSE_REASON_NONE = 0,
    VIREO_CONNECTION_CLOSE_REASON_APPLICATION = 1,
    VIREO_CONNECTION_CLOSE_REASON_PEER_EOF = 2,
    VIREO_CONNECTION_CLOSE_REASON_PROTOCOL = 3,
    VIREO_CONNECTION_CLOSE_REASON_IO = 4,
    VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP = 5,
    VIREO_CONNECTION_CLOSE_REASON_RESOURCE_LIMIT = 6
} vireo_connection_close_reason_t;

/** 按值观测，不含 fd、资源句柄或可写 view；读区积存接收字节，写区积存待发字节。 */
typedef struct vireo_connection_info {
    vireo_buffer_info_t read_buffer;  /**< 未消费接收字节的容量、长度和尾空快照。 */
    vireo_buffer_info_t write_buffer; /**< 待发 FIFO 快照；tail_space 不含已发送头洞。 */
    size_t buffer_capacity_bytes;    /**< 两个固定字节区容量之和。 */
    size_t max_buffer_bytes;         /**< 创建时提供的两字节区预算。 */
    bool read_eof;                  /**< 已观察 recv=0；永久保持，不表示 buffer 为空。 */
    bool loop_attached;             /**< 本地仍保留绑定；不证明外部 loop 存活。 */
    uint32_t loop_interests;         /**< 已提交的三项目关注位；无绑定时为 0。 */
    bool callback_active;           /**< 正在执行业务回调；仅 Reactor 时点观察。 */
    bool flow_enabled;              /**< 绑定上的帧流关注策略已启用。 */
    bool read_pressure;             /**< 上次成功同步的读压力；不会随字节操作隐式更新。 */
    bool write_pressure;            /**< 上次成功同步的写压力；不禁止排空待发队列。 */
    vireo_connection_flow_options_t flow_options; /**< 策略按值快照；禁用时全部为 0。 */
    vireo_connection_close_state_t close_state;   /**< 永久逻辑阶段，非内核状态。 */
    vireo_connection_close_mode_t close_mode;     /**< 当前模式；只可 DRAIN 升立即。 */
    vireo_connection_close_reason_t close_reason; /**< 首次原因，未请求为 NONE。 */
} vireo_connection_info_t;

/** 诊断阶段；NONE 表示成功或参数/容量拒绝，系统原因只在 IO 时有效。 */
typedef enum vireo_connection_stage {
    VIREO_CONNECTION_STAGE_NONE = 0,                /**< 成功或参数/容量拒绝。 */
    VIREO_CONNECTION_STAGE_VALIDATE_FD = 1,         /**< 创建前只读 socket 查询失败。 */
    VIREO_CONNECTION_STAGE_ALLOCATE_CONTROL = 2,    /**< 控制块申请失败。 */
    VIREO_CONNECTION_STAGE_CREATE_READ_BUFFER = 3,  /**< 读 buffer 创建失败。 */
    VIREO_CONNECTION_STAGE_CREATE_WRITE_BUFFER = 4, /**< 写 buffer 创建失败。 */
    VIREO_CONNECTION_STAGE_CLOSE_SOCKET = 5,        /**< 销毁时单次 close 失败。 */
    VIREO_CONNECTION_STAGE_RECEIVE = 6,             /**< 接收系统失败或内部不变量异常。 */
    VIREO_CONNECTION_STAGE_ENQUEUE = 7,             /**< 排队内部不变量异常。 */
    VIREO_CONNECTION_STAGE_SEND = 8                 /**< 发送系统失败或内部不变量异常。 */
} vireo_connection_stage_t;

typedef struct vireo_connection_error {
    vireo_connection_stage_t stage; /**< 此次结果对应阶段。 */
    int system_errno;              /**< IO 原 errno；其他分类为 0。 */
} vireo_connection_error_t;

/** 本轮 recv 的独立双上限；各为任意正 size_t，无默认值或额外硬限。 */
typedef struct vireo_connection_receive_budget {
    size_t max_bytes;    /**< 最多从 socket 取走的字节数，不含 compact 搬移。 */
    size_t max_syscalls; /**< 最多 recv 次数，包含短读、EOF 和失败调用。 */
} vireo_connection_receive_budget_t;

/** 停止原因按本轮实际观察；未调用 recv 时不能据满区/预算推断 EOF。 */
typedef enum vireo_connection_receive_stop {
    VIREO_CONNECTION_RECEIVE_STOP_WOULD_BLOCK = 0, /**< 实际 recv 报 EAGAIN/EWOULDBLOCK。 */
    VIREO_CONNECTION_RECEIVE_STOP_EOF = 1,         /**< 已观察 recv=0，含以前记录的 EOF。 */
    VIREO_CONNECTION_RECEIVE_STOP_BUFFER_FULL = 2, /**< 固定读区没有可追加空间。 */
    VIREO_CONNECTION_RECEIVE_STOP_BYTE_BUDGET = 3, /**< 本轮字节预算已用完。 */
    VIREO_CONNECTION_RECEIVE_STOP_CALL_BUDGET = 4, /**< 本轮 recv 次数预算已用完。 */
    VIREO_CONNECTION_RECEIVE_STOP_ERROR = 5        /**< IO 或 INTERNAL；此前进度不回滚。 */
} vireo_connection_receive_stop_t;

/** 本轮按值统计；不包含入口已有字节，也不授予 view 或资源所有权。 */
typedef struct vireo_connection_receive_info {
    size_t received_bytes;                       /**< 有效正 recv 返回的本轮字节数。 */
    size_t recv_calls;                           /**< 已执行 recv 次数。 */
    vireo_connection_receive_stop_t stop_reason; /**< 此次停止的唯一原因。 */
} vireo_connection_receive_info_t;

/**
 * @brief 创建固定双 buffer，全部就绪后接管已连接 socket
 *
 * @param[in] options
 *     非空配置，仅借用到返回；先受检容量加法，再检查正容量、硬限与预算。
 * @param[in,out] fd_owner
 *     非空独立拥有者存储，入口值 >= 0（含 0）；成功置 -1，失败保持。
 *     fd 须为调用者唯一拥有、未外部登记或并发使用的已连接 SOCK_STREAM，
 *     且已经具有 O_NONBLOCK 和 FD_CLOEXEC；禁止外部通过副本/dup 别名操作资源。
 * @param[in,out] out_connection
 *     非空独立拥有者存储，入口 *out_connection 为 NULL；成功取得唯一对象。
 * @param[out] error
 *     可空独立诊断；成功和参数/容量拒绝为 NONE/0，IO 保留原系统 errno。
 *
 * @retval VIREO_OK
 *     两个空 buffer 与 socket 全部归 connection；最终用 destroy 释放。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空、fd 为负、输出非空，或查询成功但 flags/type 不符合前置条件。
 * @retval VIREO_RESULT_OVERFLOW
 *     read_capacity + write_capacity 无法由 size_t 表示；先于容量范围检查。
 * @retval VIREO_RESULT_RANGE
 *     容量/预算为零、超过硬限，或可表示的容量合计超过预算。
 * @retval VIREO_RESULT_IO
 *     F_GETFL、F_GETFD、SO_TYPE 或 getpeername 查询失败，包含未连接/非 socket。
 * @retval VIREO_RESULT_NO_MEMORY
 *     控制块、read buffer 或 write buffer 创建失败。
 *
 * @note 查询只读，不 dup、不改属性、不自动重试；不建立连接或登记 event loop。
 * @note 失败保留两个 owner 并逆序释放已取得内存，不关闭调用者 fd。
 * @note 预算只计两块字节区；buffer 与 connection 的控制块另有申请开销。
 * @note 输入/输出/诊断存储均须有效、不重叠，且不位于本对象或自有资源内。
 * @note 线程安全：Reactor-only；不支持 signal handler、强制取消或 fork 后未 exec 使用。
 * @note errno：所有路径保持入口 errno，可空诊断不改变处理。
 */
vireo_result_t vireo_connection_create(vireo_connection_options_t const *options,
                                       int *fd_owner, vireo_connection_t **out_connection,
                                       vireo_connection_error_t *error);

/**
 * @brief 按值读取双 buffer、预算、EOF、绑定、水位快照与逻辑关闭状态
 *
 * @param[in] connection
 *     非空存活对象，仅在调用期间借用。
 * @param[out] out_info
 *     非空独立输出存储，不与对象或资源重叠。
 *
 * @retval VIREO_OK
 *     提交完整观测与读 EOF 快照，不转移资源或延长生命期，不结束 read view。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     任一参数为空；失败保持 out_info 全部字节。
 *
 * @note 不分配、不执行系统调用；线程安全：Reactor-only。
 * @note errno：不读取、不保存且不修改 errno；观测不承诺未来状态。
 */
vireo_result_t vireo_connection_inspect(vireo_connection_t const *connection,
                                        vireo_connection_info_t *out_info);

/**
 * @brief 按双预算接收原始字节，保留顺序与真实部分进度
 *
 * @param[in,out] connection
 *     非空存活对象，调用期间独占；不转移 socket 或 buffer 所有权。
 * @param[in] budget
 *     非空显式预算，两值须 > 0；借用到返回，大预算可能造成较长一轮。
 * @param[out] out_info
 *     非空独立统计；参数拒绝保持全部字节，合法接收开始后 OK/IO/INTERNAL 均提交本轮进度。
 * @param[out] error
 *     可空独立诊断；IO 记录 RECEIVE 与原 errno，成功/参数拒绝为 NONE/0。
 *
 * @retval VIREO_OK
 *     EAGAIN、EOF、满区或预算耗尽正常停止，合法收到的字节全部追加至本对象读 buffer。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空。
 * @retval VIREO_RESULT_RANGE
 *     任一预算为 0。
 * @retval VIREO_RESULT_IO
 *     recv 报其他系统错误，含 EINTR；此前已缓存字节保留，统计仍提交，不自动重试。
 * @retval VIREO_RESULT_INTERNAL
 *     原生数量或依赖违反不变量；此前缓存保持，不承诺异常一步可恢复。
 *
 * @retval VIREO_RESULT_BUSY
 *     已请求关闭；保持统计、读 buffer 与已有读借用。
 *
 * @note 允许接收时先 compact 一次并结束全部旧 read view，含零进度/IO；参数拒绝不结束 view。
 * @note recv 使用 MSG_DONTWAIT，长度不超过剩余字节预算/尾空/4096；固定栈暂存后公开 append。
 * @note 不分配/扩容；compact 可搬移未读字节，双预算不承诺总 CPU/时间上限或全局公平。
 * @note EOF 永久记录，不清空缓冲、关闭 fd 或认定 write 方向结束；以后合法调用零 recv。
 * @note 已知 EOF 优先；未实际观测系统停止时按字节预算、满区、调用预算顺序判定。
 * @note 输入/输出/诊断存储均有效且互不重叠，也不位于对象或其自有字节区内。
 * @note 线程安全：Reactor-only；旧 view 读取须先结束，不支持强制取消或信号处理器调用。
 * @note errno：所有路径保持入口 errno；IO 不等于零副作用，不会回滚 socket 已取字节。
 * @note 不解析协议帧、调整事件关注、执行发送或自动关闭。
 */
vireo_result_t vireo_connection_receive(vireo_connection_t *connection,
                                        vireo_connection_receive_budget_t const *budget,
                                        vireo_connection_receive_info_t *out_info,
                                        vireo_connection_error_t *error);

/**
 * @brief 只读借用全部未消费接收字节，不判断完整协议帧
 *
 * @param[in] connection
 *     非空存活对象，调用期间借用。
 * @param[out] out_data
 *     非空独立指针输出；成功借用只读字节，不得写入或释放，空态为 NULL。
 * @param[out] out_size
 *     非空独立长度输出；单位字节，空态为 0。
 *
 * @retval VIREO_OK
 *     同时提交指针和长度，不修改资源或结束已有 view。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     任一参数为空；两个输出全部保持。
 *
 * @note 两输出互不重叠，也不位于对象或其资源内；不接管输出存储所有权。
 * @note view 到下一次合法 receive（含零进度/IO）、成功 consume（含0）或 destroy 失效。
 * @note inspect/peek、参数拒绝及失败 consume 保持 view；复制指针不延长借用，不交给 worker。
 * @note 线程安全：Reactor-only；借用读取期间不得修改或销毁对象。
 * @note errno：不读取、不保存且不修改 errno。
 */
vireo_result_t vireo_connection_read_peek(vireo_connection_t const *connection,
                                          uint8_t const **out_data, size_t *out_size);

/**
 * @brief 消费调用者已经处理的接收前缀，保留剩余顺序
 *
 * @param[in,out] connection
 *     非空存活对象，调用期间独占；所有权不转移。
 * @param[in] size
 *     0..当前 readable_size，单位字节；0 是成功空操作。
 *
 * @retval VIREO_OK
 *     消费指定前缀；全部消费归零读写位置，任何成功均结束全部旧 view。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     connection 为空。
 * @retval VIREO_RESULT_RANGE
 *     size 超过当前未消费长度；失败保持状态及 view。
 *
 * @note 不清除 EOF、不分配/缩容/清零，不判断协议或是否真的已处理。
 * @note 线程安全：Reactor-only；借用读取须先结束。
 * @note errno：不读取、不保存且不修改 errno。
 */
vireo_result_t vireo_connection_read_consume(vireo_connection_t *connection, size_t size);

/**
 * @brief 单次关闭 socket，释放全部内存并消费拥有者句柄
 *
 * @param[in,out] connection
 *     非空独立唯一 owner 存储，*connection 可为空；存储不得位于被释放对象内。
 *     本模块管理的绑定/回调在途由 BUSY 拒绝；实际释放前须结束其他全部使用、
 *     外部登记与 read/frame 借用。
 * @param[out] error
 *     可空独立诊断；关闭失败记录 CLOSE_SOCKET 与原 errno，成功为 NONE/0。
 *
 * @retval VIREO_OK
 *     已释放并置 NULL，或入口已为空的成功空操作。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     connection 地址为空。
 * @retval VIREO_RESULT_BUSY
 *     仍保留 loop 绑定或业务回调在途；owner、资源及全部借用保持。
 * @retval VIREO_RESULT_IO
 *     close 失败；仍释放两个 buffer 和控制块、置 NULL，不重试旧 fd。
 *
 * @note OK/IO 后所有旧别名失效；IO（含 EINTR）也消费 owner，不能重试原资源。
 * @note Reactor-only，实际释放前调用者负责结束借用；BUSY 保持全部借用，不执行回调。
 * @note errno：所有路径保持入口 errno，可空诊断不改变清理。
 * @note 不隐式等待排空；无绑定/在途时提前 destroy 会放弃剩余队列，caller 负责决定。
 */
vireo_result_t vireo_connection_destroy(vireo_connection_t **connection,
                                        vireo_connection_error_t *error);

/** 入站帧的基础语义；由可信调用者选择，不从远端 flags 推断。 */
typedef enum vireo_connection_frame_direction {
    VIREO_CONNECTION_FRAME_REQUEST = 0, /**< 按请求规则验证。 */
    VIREO_CONNECTION_FRAME_RESPONSE = 1 /**< 按响应规则验证。 */
} vireo_connection_frame_direction_t;

/** 显式帧策略；不改变 connection 固定资源或原两字节区预算。 */
typedef struct vireo_connection_frame_options {
    vireo_connection_frame_direction_t direction; /**< 所选入站基础语义。 */
    size_t max_frame_bytes; /**< 含头，32..min(read_capacity,协议最大 body+32)。 */
} vireo_connection_frame_options_t;

/** 单次校验预算；不承诺 CPU 时间上限，不提供隐式默认值。 */
typedef struct vireo_connection_frame_budget {
    size_t max_messages; /**< 正消息数上限。 */
    size_t max_bytes;    /**< 正整帧字节上限，至少为 options.max_frame_bytes。 */
} vireo_connection_frame_budget_t;

/** 校验通过的完整帧；header 按值，body 仅短期只读借用。 */
typedef struct vireo_connection_frame_view {
    vireo_protocol_header_t header; /**< 宿主语义副本，不是 wire 结构体 ABI。 */
    uint8_t const *body;            /**< 空 body 为 NULL，禁止修改/跨线程持有。 */
    size_t body_size;               /**< 与 header.body_len 相同。 */
    size_t wire_size;               /**< 受检头长+body_size，用于消费完整前缀。 */
} vireo_connection_frame_view_t;

/** 本轮停止原因；预算停止不证明后续帧/EOF 已经检查。 */
typedef enum vireo_connection_frame_stop {
    VIREO_CONNECTION_FRAME_STOP_NEED_MORE = 0, /**< 尚未 EOF，剩余字节不足完整帧。 */
    VIREO_CONNECTION_FRAME_STOP_EOF = 1,       /**< 已观察 EOF，剩余字节为空。 */
    VIREO_CONNECTION_FRAME_STOP_MESSAGE_BUDGET = 2, /**< 消息数预算达到。 */
    VIREO_CONNECTION_FRAME_STOP_BYTE_BUDGET = 3,    /**< 剩余预算不足头/下一整帧。 */
    VIREO_CONNECTION_FRAME_STOP_OUTPUT_FULL = 4,    /**< 调用者数组已满。 */
    VIREO_CONNECTION_FRAME_STOP_ERROR = 5          /**< 校验或内部不变量失败。 */
} vireo_connection_frame_stop_t;

/** 已验证前缀的本轮统计，不表示调用者已经处理或消费。 */
typedef struct vireo_connection_frame_info {
    size_t frame_count; /**< 输出数组中有效前缀条数。 */
    size_t frame_bytes; /**< 有效前缀 wire_size 之和，不包括失败/半帧。 */
    vireo_connection_frame_stop_t stop_reason; /**< 本轮首个停止原因。 */
} vireo_connection_frame_info_t;

/** framing 独立问题；不是 wire status，也不是系统 errno。 */
typedef enum vireo_connection_frame_issue {
    VIREO_CONNECTION_FRAME_ISSUE_NONE = 0,            /**< 无 framing 问题。 */
    VIREO_CONNECTION_FRAME_ISSUE_CODEC = 1,           /**< codec 检测到协议问题。 */
    VIREO_CONNECTION_FRAME_ISSUE_FRAME_TOO_LARGE = 2, /**< 整帧超过本连接上限。 */
    VIREO_CONNECTION_FRAME_ISSUE_TRUNCATED = 3        /**< 已 EOF，仍有不完整帧。 */
} vireo_connection_frame_issue_t;

/** 与旧 socket error 分离，解析不执行系统调用。 */
typedef struct vireo_connection_frame_error {
    vireo_connection_frame_issue_t issue; /**< 本项诊断类别。 */
    vireo_protocol_codec_issue_t codec_issue; /**< 仅 CODEC 时具体，其余为 NONE。 */
} vireo_connection_frame_error_t;

/**
 * @brief 按预算识别未消费字节中的完整帧，不改变读缓冲
 *
 * @param[in] connection
 *     合法非空对象，仅 Reactor 使用；读容量须至少 32。
 * @param[in] options
 *     非空策略，显式方向与合法 max_frame_bytes。
 * @param[in] budget
 *     非空双正预算，max_bytes 至少容纳 max_frame_bytes。
 * @param[out] views
 *     非空调用者数组，至少 view_capacity 个有效可写记录。
 * @param[in] view_capacity
 *     正数组容量；仅写 views[0,out_info->frame_count)，其余保持。
 * @param[out] out_info
 *     必需独立输出；有效前缀即使在解析错误时也提交。
 * @param[out] error
 *     可空独立诊断，每次调用写入本轮原因；输出对象须彼此独立且不重叠输入。
 *
 * @retval VIREO_OK
 *     停于等待更多、空 EOF、双预算或输出容量；不表示全部字节处理完成。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需指针为空或 direction 未知；全部 views/info 保持。
 * @retval VIREO_RESULT_RANGE
 *     零预算/数组容量、非法帧上限、预算小于帧上限，或启用策略时超过策略帧上限；
 *     views/info 与读借用保持。
 * @retval VIREO_RESULT_PROTOCOL
 *     头/所选基础语义/CRC 非法、整帧超本连接上限或 EOF 残帧。
 * @retval VIREO_RESULT_INTERNAL
 *     受检计算或依赖不变量异常，不承诺修复损坏对象。
 *
 * @note 成功校验前缀按序输出；解析失败仍报告此前帧，不输出当前坏帧。
 * @note 不消费、重同步、compact、recv、分配、回调或关闭；重复 peek 重新校验。
 * @note 先消息预算、输出容量，再空数据/EOF；预算停止不探查后续问题。
 * @note 完整头 decode/基础验证/整帧上限后检查字节预算，完整 body 后才 CRC。
 * @note body 借用至下次合法 receive、成功 consume（含 0）或 destroy；
 *     inspect/read_peek/frames_peek、参数拒绝/失败 consume 不结束旧借用。
 * @note 调用者处理有效前缀后显式 read_consume；一次消费使所有旧 body 借用失效。
 * @note 不验证命令专属 body/schema/鉴权；CRC 不提供身份认证。所有路径保持入口 errno。
 */
vireo_result_t vireo_connection_frames_peek(vireo_connection_t const *connection,
                                            vireo_connection_frame_options_t const *options,
                                            vireo_connection_frame_budget_t const *budget,
                                            vireo_connection_frame_view_t *views,
                                            size_t view_capacity,
                                            vireo_connection_frame_info_t *out_info,
                                            vireo_connection_frame_error_t *error);

/** 单次 send 的双正上限，各允许任意正 size_t，无默认值。 */
typedef struct vireo_connection_send_budget {
    size_t max_bytes;    /**< 最多交给内核的字节数，不含排队复制/整理。 */
    size_t max_syscalls; /**< 最多 send 次数，包括短发送和失败调用。 */
} vireo_connection_send_budget_t;

/** 发送停止原因，不等于对端应用已收到或处理。 */
typedef enum vireo_connection_send_stop {
    VIREO_CONNECTION_SEND_STOP_EMPTY = 0,       /**< 用户态待发队列已空，可能零调用。 */
    VIREO_CONNECTION_SEND_STOP_WOULD_BLOCK = 1, /**< 实际 send 报 EAGAIN/EWOULDBLOCK。 */
    VIREO_CONNECTION_SEND_STOP_BYTE_BUDGET = 2, /**< 本轮确认字节预算已用完，仍有待发。 */
    VIREO_CONNECTION_SEND_STOP_CALL_BUDGET = 3, /**< 本轮调用预算已用完，仍有待发。 */
    VIREO_CONNECTION_SEND_STOP_ERROR = 4        /**< IO/INTERNAL，此前进度不回滚。 */
} vireo_connection_send_stop_t;

/** 本轮真实进度，与当前队列总长度及对端消费状态分离。 */
typedef struct vireo_connection_send_info {
    size_t sent_bytes; /**< 有效正 send 返回之和；正常依赖下已消费。 */
    size_t send_calls; /**< 实际尝试次数，包含最后失败调用。 */
    vireo_connection_send_stop_t stop_reason; /**< 本轮首个停止原因。 */
} vireo_connection_send_info_t;

/**
 * @brief 将原始待发字节完整复制到固定 FIFO，不编码协议
 *
 * @param[in,out] connection
 *     非空有效对象，仅 Reactor 线程使用，所有权不转移。
 * @param[in] bytes
 *     size 非零须非空；通过容量检查后须真实可读且稳定，不与对象或写存储重叠。
 *     允许本对象仍有效的 read/frame body 借用，返回后不保存输入地址。
 * @param[in] size
 *     复制字节数，0 可配 NULL；失败不部分复制。
 * @param[out] error
 *     可空独立诊断，不与对象/输入重叠；参数/容量拒绝为 NONE/0。
 *
 * @retval VIREO_OK
 *     全部复制或成功空操作；caller 可释放/修改其自有输入。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     connection 为 NULL 或非零 size 配 NULL bytes。
 * @retval VIREO_RESULT_OVERFLOW
 *     当前待发长度+size 不可表示，先于容量判断。
 * @retval VIREO_RESULT_RANGE
 *     单段 size 超过固定写容量，清空队列也无法容纳。
 * @retval VIREO_RESULT_BUSY
 *     单段合法但总量超容量，上层可在释放空间后显式重试。
 * @retval VIREO_RESULT_INTERNAL
 *     buffer 依赖不变量异常；不承诺修复损坏对象。
 *
 * @note 关闭期拒绝 BUSY：已请求关闭，包括合法零字节入队；缓冲保持。
 * @note 普通拒绝不读取输入字节、不改变队列/索引；合法输入总空间够时，
 *     仅在 tail_space 不足时公开 compact 写区再 append，无分配/扩容。
 * @note 不发送、登记 loop、消费 read 或结束 read/frame 借用；读区保持。
 * @note 不验证 wire/schema，不提供整帧发送或对端接收承诺；所有路径保持入口 errno。
 */
vireo_result_t vireo_connection_write_enqueue(vireo_connection_t *connection,
                                              uint8_t const *bytes, size_t size,
                                              vireo_connection_error_t *error);

/**
 * @brief 按双预算非阻塞发送，只消费内核确认的前缀
 *
 * @param[in,out] connection
 *     非空有效对象，仅 Reactor 线程使用；read_eof 不禁止发送。
 * @param[in] budget
 *     非空双正预算，max_bytes/max_syscalls 无默认值。
 * @param[out] out_info
 *     必需独立统计；参数拒绝保持，已开始的 IO/INTERNAL 仍提交真实进度。
 * @param[out] error
 *     可空独立诊断，IO 为 SEND/原 errno，其余系统原因 0；输出互不重叠输入/对象。
 *
 * @retval VIREO_OK
 *     空队列、实际 EAGAIN/EWOULDBLOCK 或预算停止；不证明对端应用已读取。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     任一必需地址为空，状态及统计保持。
 * @retval VIREO_RESULT_RANGE
 *     任一预算为 0，状态及统计保持。
 * @retval VIREO_RESULT_IO
 *     EINTR/EPIPE 等系统失败，不自动重试/关闭，保留之前进度与未发队列。
 * @retval VIREO_RESULT_INTERNAL
 *     正请求返回 0、数量非法或依赖不变量异常，立即停止，不空转。
 *
 * @retval VIREO_RESULT_BUSY
 *     逻辑阶段为 READY；统计与缓冲保持。
 *
 * @note 每次直接借用公开只读区，request<=min(待发,剩字节预算,4096)，无运行期分配。
 * @note MSG_DONTWAIT|MSG_NOSIGNAL；不改 fd 属性、进程信号 disposition 或 mask。
 * @note 空队列先于字节预算，再调用预算；失败调用也计数，正返回仅消费该数量，
 *     消费结束局部写借用，下次重新 peek；不回滚已交内核字节。
 * @note 不清空错误剩余、不记 sticky 写错误/自动 shutdown；caller 决定恢复/关闭。
 * @note 不改变读区/EOF/read/frame 借用或 loop 关注；所有路径恢复入口 errno。
 */
vireo_result_t vireo_connection_send(vireo_connection_t *connection,
                                    vireo_connection_send_budget_t const *budget,
                                    vireo_connection_send_info_t *out_info,
                                    vireo_connection_error_t *error);

/**
 * 业务代码/context 在绑定期间借用；已经执行的回调须保持至正常返回。
 * connection 只借用到返回，events 为五个 epoll 项目就绪位，不表示完整帧。
 * 可显式收发/消费/观察/更新关注/自注销；自注销后仍不能销毁或重绑本对象。
 * 回调错误由上层持有，不自动使 loop 运行失败；须有界非阻塞、正常返回。
 */
typedef void (*vireo_connection_callback_t)(vireo_connection_t *connection,
                                           uint32_t events, void *context);

/** 绑定与水位入口的独立阶段，不改变已有 socket 或 framing 诊断。 */
typedef enum vireo_connection_loop_stage {
    VIREO_CONNECTION_LOOP_STAGE_NONE = 0,   /**< 成功或本层前置拒绝。 */
    VIREO_CONNECTION_LOOP_STAGE_ATTACH = 1, /**< 公共 loop ADD 非成功。 */
    VIREO_CONNECTION_LOOP_STAGE_UPDATE = 2, /**< 公共 loop MOD 非成功。 */
    VIREO_CONNECTION_LOOP_STAGE_DETACH = 3, /**< 公共 loop DEL 非成功。 */
    VIREO_CONNECTION_LOOP_STAGE_FLOW_CONFIGURE = 4, /**< 首次配置或重配置 MOD 非成功。 */
    VIREO_CONNECTION_LOOP_STAGE_FLOW_REFRESH = 5,   /**< 显式刷新 MOD 非成功。 */
    VIREO_CONNECTION_LOOP_STAGE_REQUEST_CLOSE = 6,  /**< 关闭请求 MOD 非成功。 */
    VIREO_CONNECTION_LOOP_STAGE_CLOSE_REFRESH = 7   /**< 关闭刷新 MOD 非成功。 */
} vireo_connection_loop_stage_t;

/** 调用者持有的独立诊断；原系统原因按嵌套 loop/epoll 合同读取。 */
typedef struct vireo_connection_loop_error {
    vireo_connection_loop_stage_t stage; /**< 本项失败阶段。 */
    vireo_event_loop_error_t loop_error; /**< 依赖完整原因；本层拒绝/成功全部成员归零。 */
} vireo_connection_loop_error_t;

/**
 * @brief 将本对象的 socket 借给一个 loop，成功后发布固定业务绑定
 *
 * @param[in,out] connection
 *     非空存活唯一对象，不转移 fd 或 buffer 所有权。
 * @param[in,out] loop
 *     非空存活借用对象；登记期间不得外部更改此注册或提前关闭客户 fd。
 * @param[in] interests
 *     LT 三个 epoll 项目关注位，可为 0；未知位拒绝。
 * @param[in] callback
 *     非空借用代码，绑定期间固定，已经执行时须保持至返回。
 * @param[in] context
 *     可空借用上下文，期限同 callback；不由本对象释放。
 * @param[out] error
 *     可空独立诊断，与全部输入/资源不重叠；依赖失败保留完整 loop 原因。
 *
 * @retval VIREO_OK
 *     一次公共 ADD 成功，保存绑定；没有执行回调或收发。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需对象/代码为空或关注含未知位。
 * @retval VIREO_RESULT_BUSY
 *     已请求关闭、已绑定、本对象回调在途，或依赖注册表满；状态保持。
 * @retval VIREO_RESULT_OVERFLOW
 *     依赖数值身份耗尽。
 * @retval VIREO_RESULT_IO
 *     依赖 ADD 失败；不重试、不关闭本对象 fd。
 *
 * @note handle/fd 隐藏，所有绑定变更经本模块；失败不保存部分绑定。
 * @note loop 须保持存活；若整体销毁，须按 forget_destroyed_loop 前置清本地记录，
 *     清理前仅允许 inspect、forget_destroyed_loop 或受保护 destroy。
 * @note 零关注仍可能 ERROR/HANGUP；不自动收发、调整水位或关闭。
 * @note Reactor-only、无本层运行期分配；保持入口 errno，不结束 read/frame 借用。
 */
vireo_result_t vireo_connection_attach(vireo_connection_t *connection,
                                       vireo_event_loop_t *loop, uint32_t interests,
                                       vireo_connection_callback_t callback, void *context,
                                       vireo_connection_loop_error_t *error);

/**
 * @brief 严格一次 MOD，全替换当前绑定的关注位
 *
 * @param[in,out] connection
 *     非空存活对象，已绑定的 loop 必须仍存活；可在自己的回调中使用。
 * @param[in] interests
 *     三已知项目位，可为 0；同值更新也执行一次 MOD。
 * @param[out] error
 *     可空独立诊断；依赖失败保留完整原因。
 *
 * @retval VIREO_OK
 *     系统更新成功后才提交本地关注，其他绑定保持。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     对象为空或未知关注位。
 * @retval VIREO_RESULT_NOT_FOUND
 *     未绑定；依赖发现失效身份时也原样返回。
 * @retval VIREO_RESULT_RANGE
 *     依赖拒绝身份范围，合法未损坏绑定不会出现。
 * @retval VIREO_RESULT_BUSY
 *     已请求关闭，或帧流策略已启用；OPEN 下须先 flow_disable 才能手动控制关注。
 * @retval VIREO_RESULT_IO
 *     MOD 失败，旧关注/资源保持，不自动重试。
 *
 * @note 依赖其他非成功分类原样返回；不得外部操作隐藏注册。
 * @note Reactor-only、输入/诊断与资源独立，保持入口 errno/读借用，无自动策略。
 */
vireo_result_t vireo_connection_set_interests(vireo_connection_t *connection,
                                              uint32_t interests,
                                              vireo_connection_loop_error_t *error);

/**
 * @brief 严格注销绑定，成功后清本地记录但不关闭 socket
 *
 * @param[in,out] connection
 *     非空存活对象，绑定 loop 必须仍存活；未绑定可重复空操作。
 * @param[out] error
 *     可空独立诊断；依赖非成功保留原分类与完整原因。
 *
 * @retval VIREO_OK
 *     无绑定或一次 DEL 成功，登记借用结束并清帧流策略；执行中的回调仍须到返回。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     对象为空；依赖拒绝身份时原样返回。
 * @retval VIREO_RESULT_NOT_FOUND
 *     依赖认为身份已失效，绑定保持，不吞错误。
 * @retval VIREO_RESULT_RANGE
 *     依赖身份范围异常，绑定保持。
 * @retval VIREO_RESULT_IO
 *     DEL 失败，全部绑定/资源保持，destroy 仍 BUSY；无自动重试。
 *
 * @note 可 self-detach；返回不等于正在执行的代码/context 借用已经结束。
 * @note Reactor-only、诊断独立，保持入口 errno/读借用，不收发/free context/close。
 */
vireo_result_t vireo_connection_detach(vireo_connection_t *connection,
                                       vireo_connection_loop_error_t *error);

/**
 * @brief 在所属 loop 已彻底销毁后清除本地绑定记录
 *
 * @param[in,out] connection
 *     非空存活对象；未绑定为空操作，非空绑定必须满足下面的严格前置。
 * @param[out] error
 *     可空独立诊断，成功/拒绝为 NONE/零；不访问旧 loop。
 *
 * @retval VIREO_OK
 *     本地绑定归空；没有关闭 socket、消费 buffer 或访问旧 loop。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     对象为空。
 * @retval VIREO_RESULT_BUSY
 *     本对象回调仍在途，状态保持。
 *
 * @pre 非空绑定且回调不在途时，调用者已结束所属 loop 全部运行/停止请求者，
 *     并实际 destroy 正确 loop，
 *     包含 IO 后 owner 已被消费；只有 stop、run 返回或 destroy BUSY 都不满足。
 * @warning 无法验证悬空对象；仍存活 loop 上调用会遗留注册，属于调用者违反前置。
 * @note Reactor-only、诊断独立，保持入口 errno/读借用；不代替服务器 drain。
 */
vireo_result_t vireo_connection_forget_destroyed_loop(vireo_connection_t *connection,
                                                      vireo_connection_loop_error_t *error);

/**
 * @brief 配置帧流双迟滞水位，并从当前占用初始化关注
 *
 * @param[in,out] connection
 *     非空存活对象，须绑定存活 loop；允许在本对象回调中使用。
 * @param[in] options
 *     非空独立配置，借用到返回；32 <= max_frame_bytes <= min(读容量, 协议最大整帧)，
 *     max_frame_bytes-1 <= read_low < read_high <= 读容量，
 *     0 <= write_low < write_high <= 写容量。
 * @param[out] error
 *     可空独立诊断，不重叠输入/资源；依赖失败完整保留原 loop 诊断。
 *
 * @retval VIREO_OK
 *     从未锁状态按当前占用重算压力；关注不变或一次 MOD 成功后才发布全部策略。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空。
 * @retval VIREO_RESULT_NOT_FOUND
 *     未绑定；依赖非成功分类也原样返回。
 * @retval VIREO_RESULT_RANGE
 *     任一阈值、帧上限不满足约束；状态保持，不调用 MOD。
 * @retval VIREO_RESULT_IO
 *     MOD 失败；旧配置、压力与关注保持，不重试、不回滚此前字节进度。
 * @retval VIREO_RESULT_INTERNAL
 *     公开依赖或受检协议长度不变量异常。
 *
 * @retval VIREO_RESULT_BUSY
 *     已请求关闭；不改变原 flow 快照，关闭关注策略优先。
 *
 * @note 关闭期在必需地址检查后拒绝，不再解释新的阈值配置。
 * @note 占用 >= high 锁压力，已锁占用 <= low 解锁，中间保留；重配置不继承旧锁存。
 * @note 未 EOF 且两压力均解除才关注 READ/PEER_WRITE_CLOSED；待发非空才关注 WRITE。
 * @note 启用后手动 set_interests 返回 BUSY；frames_peek 上限超过策略上限返回 RANGE。
 * @note 字节操作不隐式同步，调用者在有界处理后 refresh；不自动收发、关闭或调度缓存帧。
 * @note Reactor-only；无运行期申请，保持入口 errno 和全部读借用；未绑定不能启用。
 */
vireo_result_t vireo_connection_flow_configure(
    vireo_connection_t *connection, vireo_connection_flow_options_t const *options,
    vireo_connection_loop_error_t *error);

/**
 * @brief 根据当前占用、EOF 和旧锁存显式同步关注
 *
 * @param[in,out] connection
 *     非空存活对象，须启用策略且绑定存活 loop；可在本对象回调中使用。
 * @param[out] error
 *     可空独立诊断；必要 MOD 失败保留完整原 loop 原因。
 *
 * @retval VIREO_OK
 *     目标关注不同才一次 MOD；相同时不调用 MOD，仍提交新压力快照。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     connection 为空。
 * @retval VIREO_RESULT_NOT_FOUND
 *     未绑定或未启用；依赖非成功分类原样返回。
 * @retval VIREO_RESULT_IO
 *     MOD 失败，保留上次成功策略/压力/关注；实际字节进度保持，可显式再刷新。
 * @retval VIREO_RESULT_INTERNAL
 *     公开 buffer 观察不变量异常。
 *
 * @retval VIREO_RESULT_BUSY
 *     已请求关闭；须用 close_refresh 同步关闭关注。
 *
 * @note 两压力只暂停接收，不暂停待发排空；EOF 关闭读关注但不丢缓冲或关闭 socket。
 * @note ERROR/HANGUP 仍由 loop 无条件保留；错误与关闭由上层处理。
 * @note 缓存完整帧因预算停止时，调用者须安排继续处理，不能只等新的 socket 就绪。
 * @note Reactor-only，无运行期分配/重试；保持入口 errno、读借用，不承诺时间公平。
 */
vireo_result_t vireo_connection_flow_refresh(vireo_connection_t *connection,
                                             vireo_connection_loop_error_t *error);

/**
 * @brief 退出帧流策略，保留已提交的当前关注
 *
 * @param[in,out] connection
 *     非空存活对象；可在回调中、未绑定或已禁用时重复调用。
 * @param[out] error
 *     可空独立诊断，成功或本层拒绝全部归零。
 *
 * @retval VIREO_OK
 *     清配置和两个压力，不访问 loop、不 MOD、不改变字节；之后可手动 set_interests。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     connection 为空。
 *
 * @retval VIREO_RESULT_BUSY
 *     已请求关闭；原 flow 快照保留到解绑清理点。
 *
 * @note detach/forget 成功也自动清策略；再次 attach 从手动模式开始。
 * @note 若原 loop 已整体销毁，仍须先按 forget_destroyed_loop 前置安全清绑定。
 * @note Reactor-only，无分配；保持入口 errno 和读借用。
 */
vireo_result_t vireo_connection_flow_disable(vireo_connection_t *connection,
                                             vireo_connection_loop_error_t *error);

/**
 * @brief 永久提交关闭意图，再同步已有队列的排空关注
 *
 * @param[in,out] connection
 *     非空存活对象，可未绑定或在自己的回调内使用；绑定 loop 必须仍存活。
 * @param[in] mode
 *     DRAIN 或 IMMEDIATE；同模式可重复，DRAIN 可升级立即，逆向拒绝。
 * @param[in] reason
 *     六个非 NONE 原因之一；仅首次合法请求记录，后续不会覆盖。
 * @param[out] error
 *     可空独立诊断，依赖失败保存 REQUEST_CLOSE 与完整原 loop 原因。
 *
 * @retval VIREO_OK
 *     意图已记录，必要一次 MOD 成功或无需 MOD；未绑定不操作 loop。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     对象为空或 mode/reason 非法；不提交意图。
 * @retval VIREO_RESULT_BUSY
 *     已 IMMEDIATE 却请求 DRAIN，状态与关注保持。
 * @retval VIREO_RESULT_IO
 *     MOD 失败；关闭意图、首原因和逻辑阶段已提交，旧关注保持，不重试。
 * @retval VIREO_RESULT_INTERNAL
 *     公开 buffer 观察异常；合法关闭意图仍保留，不承诺损坏对象可恢复。
 *
 * @note DRAIN 非空为 DRAINING/WRITE，空为 READY/0；IMMEDIATE 为 READY/0，
 *     已读/未发字节均保留到上层主动 destroy。最终响应须先入队再请求 DRAIN。
 * @note 关闭后 receive/enqueue、attach/手动关注/三 flow 变更 BUSY；
 *     send 仅 OPEN/DRAINING 可用；必需地址/枚举验证先于状态拒绝，观察/读消费仍可用。
 * @note 依赖分类原样返回；可重复请求或 close_refresh 补同步，无 reset。
 * @note 不 DEL/close/free/shutdown，不自动选策略/期限；READY 仍须成功 detach、
 *     在途回调正常返回并结束其他使用后 destroy，DEL 失败继续保留注册借用。
 * @note Reactor-only，无分配/新资源；保持入口 errno、read/frame 借用。
 */
vireo_result_t vireo_connection_request_close(
    vireo_connection_t *connection, vireo_connection_close_mode_t mode,
    vireo_connection_close_reason_t reason, vireo_connection_loop_error_t *error);

/**
 * @brief 在有界发送后更新逻辑关闭阶段，并同步 WRITE 或零关注
 *
 * @param[in,out] connection
 *     非空存活且已请求关闭对象，若绑定 loop 须仍存活；回调内可用。
 * @param[out] error
 *     可空独立诊断；必要 MOD 失败保存 CLOSE_REFRESH 与完整 loop 原因。
 *
 * @retval VIREO_OK
 *     按当前待发/模式更新阶段；mask 相同不 MOD，不同时单次成功后提交。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     connection 为空。
 * @retval VIREO_RESULT_NOT_FOUND
 *     仍为 OPEN，状态保持；依赖分类也原样返回。
 * @retval VIREO_RESULT_IO
 *     MOD 失败；新逻辑阶段仍有效，旧关注保持，不回滚已发字节或意图。
 * @retval VIREO_RESULT_INTERNAL
 *     公开 buffer 观察异常。
 *
 * @note send 不隐式刷新；最后发空后显式刷新才进入 READY 并撤 WRITE。
 * @note close 关注优先；原 flow 快照保留到旧解绑清理点，解绑不清关闭状态。
 * @note 排空仅确认字节交内核，无对端消费或时间保证，上层可升级 IMMEDIATE。
 * @note 正确 loop 已整体销毁后仍须先 forget；stop 不代替该前置或 server drain。
 * @note 不消费 owner/字节或结束读借用；Reactor-only、无分配、保持入口 errno。
 */
vireo_result_t vireo_connection_close_refresh(vireo_connection_t *connection,
                                              vireo_connection_loop_error_t *error);

#endif /* VIREO_NET_CONNECTION_H */
