/*
- PROJECT : VIREO
- FILE    : tcp_server_tls.h
- AUTHOR  : bitofux
- DATE    : 2026-10-17
- BRIEF   : 此模块负责：
- -- 同一server资源根的固定TLS模式及context唯一交接
- -- 有限准入、期限感知等待与逐租约握手/应用/关闭驱动
 */
#ifndef VIREO_NET_TCP_SERVER_TLS_H
#define VIREO_NET_TCP_SERVER_TLS_H

#include <vireo/net/tcp_server.h>
#include <vireo/net/tls_connection.h>

/** 创建时值复制；每客户容量/期限规则固定，不能热切换模式或证书。 */
typedef struct vireo_tcp_server_tls_options {
    vireo_tls_io_options_t io; /**< 原prepare八配置；读/写容量及读单元至少32字节。 */
    size_t max_wrapper_bytes; /**< 单SSL包装正上限，<=TLS包装64MiB硬限，非SSL内部总额。 */
    uint64_t handshake_timeout_ns; /**< 正纳秒时长；每次成功accept后立即固定t0+此值。 */
    size_t max_tls_resource_bytes; /**< 全根两FIFO+两16KiB暂存总限额，正且<=64MiB。 */
} vireo_tcp_server_tls_options_t;

/** 独立值快照；失败保持，不含owner/native/fd。 */
typedef struct vireo_tcp_server_tls_info {
    vireo_tcp_server_tls_options_t options; /**< 创建时固定副本。 */
    size_t per_connection_resource_bytes; /**< 读容量+写容量+32768，受检求和。 */
    size_t resource_bytes; /**< 当前客户数乘单客户固定区，含失败未归还客户。 */
    size_t available_resource_bytes; /**< 新限额减当前固定区；不是RSS余量。 */
    size_t context_wrapper_bytes; /**< owned context真实包装；已计原server总内存账。 */
} vireo_tcp_server_tls_info_t;

/** 原部分成功前缀合同；资源停止时不accept已知超额的下一客户。 */
typedef struct vireo_tcp_server_tls_admit_info {
    vireo_tcp_server_admit_info_t admission; /**< accepted=admitted+rejected，错误也提交。 */
    bool tls_resource_limited; /**< 新固定区限额停止，原stop_reason为BUFFER_LIMIT。 */
} vireo_tcp_server_tls_admit_info_t;

/** 机械等待及时间观察；每可写路径提交，不能从OK推导握手成功。 */
typedef struct vireo_tcp_server_tls_poll_report {
    vireo_tcp_server_poll_report_t poll; /**< 原实际wait/selected前缀/剩余队列报告。 */
    uint32_t listener_events; /**< 本次成功wait窗口监听事件OR，不是历史值。 */
    size_t scanned_slots; /**< 最多两次固定N槽检查，非O(1)调度器。 */
    size_t expired_clients; /**< 后扫描发现的握手或关闭活跃到期客户，含本已排队者。 */
    bool has_deadline; /**< 前扫描是否存在活跃握手或关闭due，0本身不是空哨兵。 */
    vireo_monotonic_ns_t nearest_deadline_ns; /**< 前扫描握手/关闭最近绝对期限。 */
    vireo_monotonic_ns_t before_wait_ns; /**< 成功前采时；未采得为0，依stage判断有效。 */
    vireo_monotonic_ns_t after_wait_ns; /**< 成功后采时；未采得为0。 */
} vireo_tcp_server_tls_poll_report_t;

/** 原TLS握手事实与epoll关注提交分别报告；失败也可能已建立。 */
typedef struct vireo_tcp_server_tls_handshake_info {
    vireo_tls_handshake_info_t handshake; /**< 本次真实状态/最新WANT/是否调用native。 */
    vireo_monotonic_ns_t now_ns; /**< 本次成功采样值；看sampled/step_called判断有效性。 */
    bool sampled; /**< 时钟成功，不代表TLS步进已执行。 */
    bool step_called; /**< 已调用原step_at；原生前拒绝也为true。 */
    bool handshake_reported; /**< 原step真正发布报告，原生前拒绝为false；此时handshake全零。 */
    bool sync_called; /**< 目标mask与实际不同，已尝试set_interests。 */
    uint32_t interests; /**< 返回时实际已提交mask，MOD失败仍为旧值。 */
    bool application_ready; /**< 握手已建立，须转交显式应用路径；不承诺应用健康。 */
    bool retry_pending; /**< MOD失败后成功安排一次原FIFO恢复待办。 */
} vireo_tcp_server_tls_handshake_info_t;

/** 主失败阶段；成功/基本拒绝NONE。握手主因与关注次因互不覆盖。 */
typedef enum vireo_tcp_server_tls_stage {
    VIREO_TCP_SERVER_TLS_NONE = 0, /**< 成功或基本参数拒绝，无主失败阶段。 */
    VIREO_TCP_SERVER_TLS_CONTEXT = 1, /**< context公开配置检查。 */
    VIREO_TCP_SERVER_TLS_CREATE_SERVER = 2, /**< 空server/loop/pool构造及回滚。 */
    VIREO_TCP_SERVER_TLS_INSPECT = 3, /**< 资源或客户公开快照检查。 */
    VIREO_TCP_SERVER_TLS_ACCEPT = 4, /**< 一次有界accept。 */
    VIREO_TCP_SERVER_TLS_CLOCK = 5, /**< 本次单调时间采集。 */
    VIREO_TCP_SERVER_TLS_DEADLINE = 6, /**< 受检期限加法或毫秒裁剪。 */
    VIREO_TCP_SERVER_TLS_CREATE_CLIENT = 7, /**< 逐连接TLS组合创建。 */
    VIREO_TCP_SERVER_TLS_PREPARE = 8, /**< 握手前固定应用资源准备。 */
    VIREO_TCP_SERVER_TLS_ARM = 9, /**< 一次固定握手期限装载。 */
    VIREO_TCP_SERVER_TLS_ADOPT = 10, /**< 唯一connection owner入池。 */
    VIREO_TCP_SERVER_TLS_LOOKUP = 11, /**< 当前租约核验或公开TLS短借。 */
    VIREO_TCP_SERVER_TLS_ATTACH = 12, /**< 客户注册到loop。 */
    VIREO_TCP_SERVER_TLS_QUEUE = 13, /**< 初次/到期/恢复队列或有限选择。 */
    VIREO_TCP_SERVER_TLS_SCAN_BEFORE = 14, /**< 等待前活跃期限扫描。 */
    VIREO_TCP_SERVER_TLS_WAIT = 15, /**< 本次loop等待。 */
    VIREO_TCP_SERVER_TLS_SCAN_AFTER = 16, /**< 等待后到期扫描和排队。 */
    VIREO_TCP_SERVER_TLS_HANDSHAKE = 17, /**< 原TLS单步/首错返回。 */
    VIREO_TCP_SERVER_TLS_SYNC = 18 /**< 原步进成功后的关注提交失败。 */
} vireo_tcp_server_tls_stage_t;

/** 各原因按值保存；未参与字段零，不保存证书文本/资源/借用。 */
typedef struct vireo_tcp_server_tls_error {
    vireo_tcp_server_tls_stage_t stage; /**< 原主因阶段，不因清理或MOD次错覆盖。 */
    vireo_tcp_server_error_t server_error; /**< 原资源构造/回滚诊断。 */
    vireo_tcp_server_client_error_t client_error; /**< 原accept/connection/pool/attach及首清理错。 */
    vireo_tls_context_error_t context_error; /**< context公开检查原因。 */
    vireo_tls_connection_error_t tls_error; /**< prepare/arm/观察/握手原因。 */
    vireo_clock_error_t clock_error; /**< 原公开单调时钟原因。 */
    vireo_event_loop_error_t loop_error; /**< 等待原因。 */
    vireo_result_t sync_result; /**< 关注同步独立结果；无尝试/成功均OK。 */
    vireo_connection_loop_error_t sync_loop_error; /**< MOD首错，不覆盖握手首因。 */
    vireo_result_t queue_result; /**< MOD失败后恢复排队结果，不替换原主要返回值。 */
} vireo_tcp_server_tls_error_t;

/**
 * @brief 创建固定TLS模式server，最后原子交接context与server两owner
 *
 * @param[in] options
 *     原四配置；TLS模式max_memory_bytes另含context真实包装。
 * @param[in] tls_options
 *     非空固定配置，pair需容纳于原pool额度，pair+32768需容纳于新额度。
 * @param[in,out] context_owner
 *     非空独立地址且持存活context唯一owner；成功清NULL，失败保持。
 * @param[in,out] out_server
 *     非空独立NULL owner；成功后用原destroy配对，失败保持。
 * @param[out] error
 *     可空独立诊断，每可写路径覆盖。
 *
 * @retval VIREO_OK
 *     完整空根发布；没有listener/客户/握手或网络。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址/owner/正配置不合法。
 * @retval VIREO_RESULT_RANGE
 *     配置/预算不足或超硬限。
 * @retval VIREO_RESULT_OVERFLOW
 *     受检容量求和不可表示。
 * @retval VIREO_RESULT_NO_MEMORY
 *     资源分配失败。
 * @retval VIREO_RESULT_IO
 *     原loop资源创建失败。
 * @retval VIREO_RESULT_INTERNAL
 *     context或原资源不变量异常。
 *
 * @note 同Reactor串行；只成功才move，无热重配或混合RAW客户；本入口不预留辅助容量。
 *     原max_memory不含逐客户控制块/SSL内部；新额度仅四应用字节区，非RSS上限。
 *     所有入口保持errno；地址存活/对齐、独立不重叠、不位于自有资源或errno。
 *     合法TLS观察/操作沿原合同清线程OpenSSL错误队列，纯基本拒绝不触库。
 *     无并发销毁/signal-handler/fork后未exec调用；跨线程仅原request_stop例外。
 */
vireo_result_t vireo_tcp_server_create_tls(vireo_tcp_server_options_t const *options,
    vireo_tcp_server_tls_options_t const *tls_options, vireo_tls_context_t **context_owner,
    vireo_tcp_server_t **out_server, vireo_tcp_server_tls_error_t *error);

/**
 * @brief 创建预留显式辅助注册容量的固定TLS根，成功才交接context
 *
 * @param[in] options
 *     非空原server四配置；max_memory_bytes含context包装与额外注册表实际申请。
 * @param[in] tls_options
 *     非空原固定TLS配置，数值/四区计费沿create_tls，不保存选项地址。
 * @param[in] auxiliary_capacity
 *     正size_t注册元素数；客户容量+1个listener+本值受检求和且不超过65536。
 * @param[in,out] context_owner
 *     非空独立地址，持存活context唯一owner；成功清NULL，失败保持。
 * @param[in,out] out_server
 *     非空独立空owner；成功发布后用原destroy配对，失败保持。
 * @param[out] error
 *     可空独立诊断，每可写路径覆盖；原根错误保存在server_error。
 *
 * @retval VIREO_OK
 *     完整空TLS根发布；尚无listener、客户、辅助绑定或原生握手。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     零辅助容量或原必需地址/owner/正配置拒绝。
 * @retval VIREO_RESULT_RANGE
 *     原配置超限、总注册超过65536或真实资源预算不足。
 * @retval VIREO_RESULT_OVERFLOW
 *     总注册受检加法不可表示。
 * @retval VIREO_RESULT_NO_MEMORY
 *     原资源分配失败，保留context并清理已取得的根资源。
 * @retval VIREO_RESULT_IO
 *     原loop创建等系统失败，原主因及回滚次因分别保留。
 * @retval VIREO_RESULT_INTERNAL
 *     原context/loop/pool不变量异常，不发布半根。
 *
 * @note 先拒绝零辅助容量，其他验证次序沿create_tls；进入原根构造的失败
 *     为CREATE_SERVER并嵌套原具体阶段。旧create_tls仍预留0且保持原签名/预算。
 *     只增加同loop固定表容量，不增加客户数、TLS字节额度、fd或活动辅助源数量；
 *     原server仍仅一个辅助绑定，notifier fd由外部owner持有，沿原register/unregister借用。
 *     同Reactor串行，保持errno；输入/输出/资源/errno存活、对齐、独立不重叠。
 *     context最后才move，无热扩容或新调度策略；TLS错误队列、禁止POSIX取消/
 *     并发销毁/signal-handler/fork后未exec复用及跨线程stop例外沿create_tls。
 *     预算不含OpenSSL内部总内存/内核/RSS；不承诺分配或系统资源创建硬实时。
 */
vireo_result_t vireo_tcp_server_create_tls_with_auxiliary_capacity(
    vireo_tcp_server_options_t const *options, vireo_tcp_server_tls_options_t const *tls_options,
    size_t auxiliary_capacity, vireo_tls_context_t **context_owner,
    vireo_tcp_server_t **out_server, vireo_tcp_server_tls_error_t *error);

/**
 * @brief 观察TLS固定配置与真实计费，不推进网络或采时
 *
 * @param[in] server
 *     非空存活TLS根，同Reactor短借。
 * @param[out] out_info
 *     非空独立快照，失败保持。
 * @param[out] error
 *     可空独立本次诊断。
 *
 * @retval VIREO_OK
 *     完整提交固定配置及当前计费。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空。
 * @retval VIREO_RESULT_BUSY
 *     RAW根没有TLS配置。
 * @retval VIREO_RESULT_OVERFLOW
 *     当前总资源受检乘法不可表示。
 * @retval VIREO_RESULT_IO
 *     原依赖检查IO原因。
 * @retval VIREO_RESULT_INTERNAL
 *     原资源或当前计费不变量异常。
 *
 * @note 无owner交接；计费含失败未release者；串行/地址/errno沿构造合同。
 */
vireo_result_t vireo_tcp_server_tls_inspect(vireo_tcp_server_t const *server,
    vireo_tcp_server_tls_info_t *out_info, vireo_tcp_server_tls_error_t *error);

/**
 * @brief 显式有界接入TLS客户；成功accept后立即采时，prepare耗时计入固定due
 *
 * @param[in,out] server
 *     非空存活TLS根，已拥有listener；READ/绑定开关不限，无其他在途。
 * @param[in] budget
 *     原双正预算（accepts<=65535）。
 * @param[out] out_clients
 *     独立租约数组，可能使用的前缀入口全零；只写admitted前缀。
 * @param[in] capacity
 *     数组正容量<=65535，实际取min(capacity,max_accepts)。
 * @param[out] out_info
 *     必需进度；前置拒绝保持，开始执行后即使失败也提交。
 * @param[out] error
 *     可空独立主因/首清理错。
 *
 * @retval VIREO_OK
 *     正常完成，含条数/调用/槽/字节额度或WOULD_BLOCK停止。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址/正预算/空租约输出不合法。
 * @retval VIREO_RESULT_RANGE
 *     正条数或容量超过硬限。
 * @retval VIREO_RESULT_BUSY
 *     RAW根或本server其他阶段在途。
 * @retval VIREO_RESULT_NOT_FOUND
 *     尚无owned listener，或依赖租约异常拒绝。
 * @retval VIREO_RESULT_OVERFLOW
 *     accept后due加法或计数不可表示。
 * @retval VIREO_RESULT_NO_MEMORY
 *     connection/TLS/缓冲/池依赖资源失败。
 * @retval VIREO_RESULT_IO
 *     accept/采时/登记依赖失败，真实原errno保存在对应原因。
 * @retval VIREO_RESULT_INTERNAL
 *     依赖或队列不变量异常；错误不撤回已发布前缀。
 *
 * @note accept前检查槽及两额度；create→prepare→arm→adopt→attach后提交租约/计费再入队。
 *     提交后队列损坏返回INTERNAL且当前仍计admitted，保持可见租约；不保证坏链修复。
 *     无native握手/RAW flow/MOD压力刷新。满额由caller暂停listener READ，归还后显式恢复。
 *     失败按当前唯一owner逆序清理，未绑定池租约可release，fd单次close不重试EINTR。
 *     串行/地址/errno/库队列沿构造合同；并不限制一次SSL内部申请或调用耗时。
 */
vireo_result_t vireo_tcp_server_tls_admit_batch(vireo_tcp_server_t *server,
    vireo_tcp_server_admit_budget_t const *budget, vireo_connection_pool_lease_t *out_clients,
    size_t capacity, vireo_tcp_server_tls_admit_info_t *out_info, vireo_tcp_server_tls_error_t *error);

/**
 * @brief 验证当前租约后短借同一Vireo TLS对象，失败保持输出
 *
 * @param[in,out] server
 *     非空存活TLS根，无其他在途；同Reactor串行。
 * @param[in] client
 *     完整当前pool/slot/generation数值租约，不保活。
 * @param[out] out_tls
 *     非空独立输出，仅借用，无destroy/move/native/fd权限。
 * @param[out] error
 *     可空独立诊断。
 *
 * @retval VIREO_OK
 *     成功短借当前客户内TLS对象。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空或租约形状/所属池不合法。
 * @retval VIREO_RESULT_NOT_FOUND
 *     已释放或旧代际租约。
 * @retval VIREO_RESULT_BUSY
 *     RAW根或本server其他阶段在途。
 * @retval VIREO_RESULT_INTERNAL
 *     原池查找与本server客户身份不一致。
 *
 * @note 借用在release/destroy前结束；应用/关闭操作后caller负责公开关注同步和续调度。
 *     不由借用推导自动TLS业务轮；地址/errno沿构造合同，借用自身无库/网络操作。
 */
vireo_result_t vireo_tcp_server_client_tls_borrow(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tls_connection_t **out_tls,
    vireo_tcp_server_tls_error_t *error);

/**
 * @brief 一次握手/关闭期限感知等待，交付有限租约；不在扫描/回调中驱动TLS
 *
 * @param[in,out] server
 *     非空TLS根，已拥有且绑定listener，无其他在途。
 * @param[in] timeout_ms
 *     非负有限毫秒等待上限，已有待办强制0，最近due再裁剪。
 * @param[in] max_clients
 *     正选择上限<=65535。
 * @param[out] out_clients
 *     独立数组，仅写实际selected_count前缀；events=0也须处理。
 * @param[in] capacity
 *     正数组容量<=65535，每租约本轮至多一次。
 * @param[out] report
 *     必需独立报告，每可写路径提交进度，不偷取未披露客户。
 * @param[out] error
 *     可空独立本次诊断，区分前扫描/采时/等待/后扫描。
 *
 * @retval VIREO_OK
 *     一次机械等待/有限交付成功，含停止零选择或无事件。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空、负timeout或零条数/容量。
 * @retval VIREO_RESULT_RANGE
 *     条数或容量超过硬限。
 * @retval VIREO_RESULT_BUSY
 *     RAW根或本server其他阶段在途。
 * @retval VIREO_RESULT_NOT_FOUND
 *     没有owned bound listener或依赖租约异常拒绝。
 * @retval VIREO_RESULT_IO
 *     采时/等待等依赖失败，原因保存在clock/loop字段。
 * @retval VIREO_RESULT_OVERFLOW
 *     原单调时钟值不可表示。
 * @retval VIREO_RESULT_INTERNAL
 *     TLS观察/期限/原队列不变量异常。
 *
 * @note 失败保留已排到期待办与真实选择前缀。
 * @note 最多2N槽检查及常数次采时，无申请；ceil毫秒可多不足1ms，不承诺硬实时。
 *     握手FAILED不参加due扫描；ESTABLISHED仅活跃close参加原关闭due扫描；原FIFO顺序/去重保持，stop不释放资源。
 *     无native/close/业务，调用者随后逐租约step；串行/地址/errno沿构造合同。
 */
vireo_result_t vireo_tcp_server_tls_poll_ready_once(vireo_tcp_server_t *server,
    int timeout_ms, size_t max_clients, vireo_tcp_server_ready_client_t *out_clients,
    size_t capacity, vireo_tcp_server_tls_poll_report_t *report, vireo_tcp_server_tls_error_t *error);

/**
 * @brief 新采时后对一个绑定TLS客户最多推进一次原生握手，并同步真实关注
 *
 * @param[in,out] server
 *     非空TLS根，无其他在途；同Reactor，不在loop callback内调用。
 * @param[in] client
 *     当前完整数值租约且仍绑定，终态重试不重新握手/续期。
 * @param[out] out_info
 *     必需独立报告，每可写路径提交采时/步进/同步实际进度。
 * @param[out] error
 *     可空独立主因及sync_result/原因、恢复排队结果。
 *
 * @retval VIREO_OK
 *     WANT或已建立，须看handshake_reported/state；不是整条会话完成。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址/租约形状不合法，或真正原生前SIGPIPE策略不符。
 * @retval VIREO_RESULT_RANGE
 *     原TLS时间域或依赖数值拒绝。
 * @retval VIREO_RESULT_BUSY
 *     RAW根、其他阶段在途，或原TLS前置拒绝。
 * @retval VIREO_RESULT_NOT_FOUND
 *     旧租约或当前客户已经未绑定。
 * @retval VIREO_RESULT_OVERFLOW
 *     时钟转换不可表示。
 * @retval VIREO_RESULT_TIMEOUT
 *     原固定握手due到期或重复首错，无新原生握手。
 * @retval VIREO_RESULT_PROTOCOL
 *     原TLS致命协议失败或重复首错。
 * @retval VIREO_RESULT_NO_MEMORY
 *     原TLS明确资源失败或重复首错。
 * @retval VIREO_RESULT_IO
 *     原采时/握手/关注依赖IO；握手主错优先，MOD次因独立。
 * @retval VIREO_RESULT_INTERNAL
 *     原依赖、握手报告或本层不变量异常。
 *
 * @note 原步进OK而MOD失败返回MOD分类；不close或假装回滚握手。
 * @note 稳定SIG_IGN前置沿原TLS；server不修改进程信号。握手与关注各自提交、不回滚。
 *     WANT_READ/WRITE提交相应方向|RDHUP，建立READ|RDHUP，失败0；mask相同不MOD。
 *     MOD失败排一次恢复，正常WANT不立即空转；终态重试零native。若原生前拒绝，
 *     不根据零初始化报告改关注。application_ready只交接，应用自动轮/关闭仍后续。
 *     不close/自动release；失败资源占账至归还；串行/地址/errno/库队列沿构造合同。
 */
vireo_result_t vireo_tcp_server_client_tls_handshake_step(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_tls_handshake_info_t *out_info,
    vireo_tcp_server_tls_error_t *error);

/** 一次应用轮三个独立预算；receive/send限制SSL调用次数，不是syscall数。 */
typedef struct vireo_tcp_server_tls_drive_budget {
    vireo_tls_io_budget_t receive; /**< 明文/原生次数；字节至少min(16384,读容量)。 */
    vireo_tcp_server_process_budget_t process; /**< 旧消息/请求/响应预算，沿最大帧保守预留。 */
    vireo_tls_io_budget_t send; /**< 明文/原生次数；字节至少min(16384,写容量)。 */
} vireo_tcp_server_tls_drive_budget_t;

/** 实际关注与一次原FIFO续调度事实，不包含目标mask或owner。 */
typedef struct vireo_tcp_server_tls_flow_info {
    vireo_tls_io_flow_t flow; /**< flow_reported时有效的真实TLS建议。 */
    uint32_t interests; /**< 成功观察到的实际mask；MOD失败保持旧值，未观察为0。 */
    bool flow_reported; /**< TLS已发布flow；不能用全零推断其实际状态。 */
    bool sync_called; /**< 目标不同，已尝试一次公开set_interests。 */
    bool queue_called; /**< 已尝试一次去重queue_append，含MOD恢复。 */
    bool continuation_pending; /**< 本次入队成功；原FIFO每客户至多一位置。 */
} vireo_tcp_server_tls_flow_info_t;

/** 各子阶段独立提交，首错后不回滚；未调用/未发布的子报告typed零。 */
typedef struct vireo_tcp_server_tls_drive_info {
    vireo_tls_io_progress_t receive; /**< receive_reported时有效，含fatal前已确认前缀。 */
    vireo_tcp_server_process_info_t process; /**< process_called时实际处理报告。 */
    vireo_tls_io_progress_t send; /**< send_reported时有效，不能从入队统计推导已发送。 */
    bool receive_called; /**< 已进入原receive，包括原生前拒绝及FAILED首错重现。 */
    bool receive_reported; /**< 原receive实际发布报告；不等native_calls非零。 */
    bool process_called; /**< 已进入原有界处理核心；handler_calls另计。 */
    bool send_called; /**< 已进入原send；每轮至多一次。 */
    bool send_reported; /**< 原send实际发布报告。 */
    bool needs_processing; /**< 成功处理因预算/写满停止后的保守缓存续探，非完整帧证明。 */
    vireo_tcp_server_tls_flow_info_t sync; /**< 末尾真实flow/关注/原FIFO提交事实。 */
} vireo_tcp_server_tls_drive_info_t;

/** 应用组合层阶段，与原TLS/native阶段分开。 */
typedef enum vireo_tcp_server_tls_application_stage {
    VIREO_TCP_SERVER_TLS_APPLICATION_NONE = 0, /**< 成功或基本数值/状态拒绝。 */
    VIREO_TCP_SERVER_TLS_APPLICATION_LOOKUP = 1, /**< 租约/当前绑定/TLS短借。 */
    VIREO_TCP_SERVER_TLS_APPLICATION_INSPECT = 2, /**< 真实状态/容量/实际mask观察。 */
    VIREO_TCP_SERVER_TLS_APPLICATION_RECEIVE = 3, /**< 一次原TLS接收或FAILED首错重现。 */
    VIREO_TCP_SERVER_TLS_APPLICATION_PROCESS = 4, /**< 原帧/handler/编码/入队/消费。 */
    VIREO_TCP_SERVER_TLS_APPLICATION_SEND = 5, /**< 一次原TLS发送。 */
    VIREO_TCP_SERVER_TLS_APPLICATION_FLOW = 6, /**< 纯TLS迟滞/调度建议刷新。 */
    VIREO_TCP_SERVER_TLS_APPLICATION_SYNC = 7, /**< 真实epoll关注提交。 */
    VIREO_TCP_SERVER_TLS_APPLICATION_QUEUE = 8 /**< 原FIFO续调度或恢复入队。 */
} vireo_tcp_server_tls_application_stage_t;

/** 主数据原因与末尾同步/队列次因独立保存；无证书/借用/owner。 */
typedef struct vireo_tcp_server_tls_application_error {
    vireo_tcp_server_tls_application_stage_t stage; /**< 本次主失败阶段。 */
    vireo_tls_connection_error_t tls_error; /**< 主TLS观察/收发/中间flow原因。 */
    vireo_tcp_server_client_error_t client_error; /**< 主旧process或租约原因。 */
    vireo_result_t sync_result; /**< 末尾观察/flow/MOD结果；未调用/成功为OK。 */
    vireo_tcp_server_tls_application_stage_t sync_stage; /**< 独立同步失败阶段，成功为NONE。 */
    vireo_tls_connection_error_t sync_tls_error; /**< 末尾TLS原因，不覆盖主TLS首因。 */
    vireo_connection_loop_error_t sync_loop_error; /**< MOD失败原原因。 */
    vireo_result_t queue_result; /**< 独立入队结果；未调用/成功为OK，不回滚任何进度。 */
} vireo_tcp_server_tls_application_error_t;

/**
 * @brief 刷新一个TLS应用客户的真实关注及本地读写待办，不执行native或handler
 *
 * @param[in,out] server
 *     非空TLS根，同Reactor串行，无其他阶段在途。
 * @param[in] client
 *     当前完整租约且仍绑定；握手已建立、I/O OPEN或FAILED、close NONE。
 * @param[out] out_info
 *     非空独立报告，每可写路径覆盖；flow_reported及sync_called区分有效进度。
 * @param[out] error
 *     可空独立原因；失败也提交主阶段/同步/队列事实。
 *
 * @retval VIREO_OK
 *     真实关注同步完成；FAILED只清关注并不返回缓存首错或释放资源。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址/租约形状/所属池不合法。
 * @retval VIREO_RESULT_BUSY
 *     RAW根、同server在途、握手未完成、应用未启用或已请求关闭。
 * @retval VIREO_RESULT_NOT_FOUND
 *     已释放/旧租约或客户未绑定。
 * @retval VIREO_RESULT_IO
 *     原公开MOD依赖失败，原errno在sync_loop_error中。
 * @retval VIREO_RESULT_INTERNAL
 *     观察/队列/状态不变量异常；其他依赖已知分类沿原结果返回。
 *
 * @note want_read/write映射READ/WRITE并附RDHUP，FAILED目标0；mask相同不MOD。
 *     成功时仅resume_read/write触发一次原FIFO去重入队；read_size/SSL_has_pending本身不触发。
 *     MOD失败也尝试一次恢复入队，实际mask仍为旧值；反复失败由caller决定何时重试/释放。
 *     外部入队/消费后可调用本入口；有缓存业务待处理时另显式schedule，不能猜最大帧。
 *     不收发/握手/采时/分配/等待/关闭/归还，不重放业务；资源仍占原账至release。
 * @note 借用/独立地址/errno/库错误队列沿本头构造合同；全部报告为值，不保活对象。
 *     纯刷新不查询SIGPIPE，不授予不满足SIG_IGN时执行TLS网络的权限。
 */
vireo_result_t vireo_tcp_server_client_tls_flow_refresh(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_tls_flow_info_t *out_info,
    vireo_tcp_server_tls_application_error_t *error);

/**
 * @brief 有界驱动一个TLS应用客户，复用唯一FIFO和原同步处理核心后提交实际关注
 *
 * @param[in,out] server
 *     非空TLS根，同Reactor、无其他阶段在途；handler期间同server可变入口BUSY。
 * @param[in] client
 *     当前完整且仍绑定租约；阶段要求沿flow_refresh，FAILED只重现首错和清关注。
 * @param[in] options
 *     非空独立两帧上限，入口复制；request另须<=TLS max_read_unit_bytes。
 * @param[in] budget
 *     非空独立三预算，入口复制；收发次数正、字节分别至少min(16384,相应FIFO容量)，
 *     也不得小于当前locked请求；process沿原最大帧预留。
 * @param[in,out] wire_workspace
 *     非空caller独立可写区，只借至返回；至少最大响应整帧，不得与自有缓冲重叠。
 * @param[in] workspace_capacity
 *     实际可写容量，只允许最大响应帧前缀变化。
 * @param[in] handler
 *     非空原同步有界/非阻塞/正常返回回调；不保留请求/工作区或修改同server。
 * @param[in,out] context
 *     可空短借context，活至返回，不长期保存。
 * @param[out] out_info
 *     必需独立真实进度，每可写路径覆盖；called与reported区分原生前拒绝。
 * @param[out] error
 *     可空独立诊断；主数据首因、末尾同步、队列原因分别保存。
 *
 * @retval VIREO_OK
 *     本轮WANT/预算/NEED_MORE/EOF或完整处理均可能，须读各报告。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址/租约不合法，或原生前SIGPIPE策略拒绝。
 * @retval VIREO_RESULT_RANGE
 *     预算/帧上限/工作区不足或handler响应超界；执行前拒绝不调用handler/native/MOD。
 * @retval VIREO_RESULT_BUSY
 *     模式/在途/握手/关闭前置拒绝，或handler/依赖BUSY。
 * @retval VIREO_RESULT_NOT_FOUND
 *     旧租约/未绑定，或原依赖失败。
 * @retval VIREO_RESULT_PROTOCOL
 *     TLS首错、裸EOF、CRC/请求/响应/EOF残帧错误。
 * @retval VIREO_RESULT_IO
 *     原TLS信号查询/SYSCALL、MOD或handler IO错误。
 * @retval VIREO_RESULT_NO_MEMORY
 *     原TLS明确malloc失败或handler资源错误；本入口不申请缓冲。
 * @retval VIREO_RESULT_OVERFLOW
 *     原响应长度checked或handler报告溢出。
 * @retval VIREO_RESULT_TIMEOUT
 *     handler报告超时；本入口不创建应用期限。
 * @retval VIREO_RESULT_CANCELLED
 *     handler报告协作取消；本入口不创建取消引用。
 * @retval VIREO_RESULT_DATABASE
 *     handler依赖分类；不得因此在Reactor阻塞执行DB。
 * @retval VIREO_RESULT_INTERNAL
 *     原依赖/队列/报告不变量或未知handler分类。
 *
 * @note WRITE优先重试先send，READ-WANT_WRITE先receive；每方向至多一次原函数调用，
 *     预算整轮不重领。新读暂停不跳过缓存process；尾部未send过且允许时再send。
 *     首错停止后续数据阶段，仍一次末尾真实flow/MOD；主错优先，不回滚响应/消费/已发前缀。
 *     同步失败先用flow_refresh恢复，不能为补MOD盲重放handler；handler/消费异常无安全重放保证。
 * @note 成功处理因预算/WRITE_FULL停止、有缓存且最终写余量足够最大响应才needs_processing；
 *     与TLS resume合并为一次FIFO待办。NEED_MORE不以read_size排队；纯WANT等待网络方向。
 *     数据失败不自动排数据重试，只有MOD失败可排一次恢复；不自动close/release或解释HUP为EOF。
 * @note 收发继承稳定SIG_IGN前置；server不修改进程信号。保持入口errno，原诊断完整按值保存。
 *     借用/地址/库队列沿flow_refresh；有限字节/SSL调用/消息预算不承诺硬实时或SSL内部RSS上限。
 */
vireo_result_t vireo_tcp_server_client_tls_drive(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_process_options_t const *options,
    vireo_tcp_server_tls_drive_budget_t const *budget, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_tls_drive_info_t *out_info, vireo_tcp_server_tls_application_error_t *error);

/** server组合阶段；TLS原state/operation/wait/stop枚举保持。 */
typedef enum vireo_tcp_server_tls_close_stage {
    VIREO_TCP_SERVER_TLS_CLOSE_NONE = 0, /**< 无主失败或尚无依赖失败。 */
    VIREO_TCP_SERVER_TLS_CLOSE_LOOKUP, /**< 租约/绑定及TLS短借。 */
    VIREO_TCP_SERVER_TLS_CLOSE_INSPECT, /**< 阶段/容量/实际登记观察。 */
    VIREO_TCP_SERVER_TLS_CLOSE_CLOCK, /**< 新单调采样。 */
    VIREO_TCP_SERVER_TLS_CLOSE_DEADLINE, /**< 受检计算请求总期限。 */
    VIREO_TCP_SERVER_TLS_CLOSE_REQUEST, /**< 原TLS关闭请求。 */
    VIREO_TCP_SERVER_TLS_CLOSE_STEP, /**< 原TLS单步或子报告校验。 */
    VIREO_TCP_SERVER_TLS_CLOSE_SYNC, /**< 真实关注MOD。 */
    VIREO_TCP_SERVER_TLS_CLOSE_QUEUE /**< 无更高优先错误时的入队原因。 */
} vireo_tcp_server_tls_close_stage_t;

/** 值报告不保活owner；所有新入口在每条可写路径typed覆盖。 */
typedef struct vireo_tcp_server_tls_close_flow_info {
    vireo_tls_close_info_t close; /**< 最终真实关闭快照。 */
    uint32_t interests; /**< 实际mask；MOD失败仍是旧mask。 */
    bool close_reported; /**< close已发布，不以全零猜状态。 */
    bool sync_called; /**< 是否实际尝试MOD。 */
    bool queue_called; /**< 是否尝试一次去重入队。 */
    bool continuation_pending; /**< 本次入队成功，可能此前已在FIFO。 */
} vireo_tcp_server_tls_close_flow_info_t;

/** 采时、期限计算、封口提交和同步分别发布；失败不能撤销requested。 */
typedef struct vireo_tcp_server_tls_close_request_info {
    vireo_monotonic_ns_t now_ns; /**< 首次采时数值。 */
    vireo_monotonic_ns_t deadline_ns; /**< checked计算的唯一总期限。 */
    bool sampled; /**< now有效，0也是合法值。 */
    bool deadline_computed; /**< deadline有效。 */
    bool request_called; /**< 已调用原request，失败不等于封口。 */
    bool requested; /**< 原request成功；后续失败不撤销。 */
    vireo_tcp_server_tls_close_flow_info_t sync; /**< 最终同步事实。 */
} vireo_tcp_server_tls_close_request_info_t;

/** 一次有界关闭的真实子进度与末尾同步；called不保证子报告已发布。 */
typedef struct vireo_tcp_server_tls_close_step_info {
    vireo_tls_close_progress_t progress; /**< 仅progress_reported时解释。 */
    vireo_monotonic_ns_t now_ns; /**< 活跃阶段新采时，终态不用。 */
    bool sampled; /**< 本次采时成功。 */
    bool step_called; /**< 原step已尝试；原生前也可拒绝。 */
    bool progress_reported; /**< 原step实际发布了子报告。 */
    vireo_tcp_server_tls_close_flow_info_t sync; /**< 失败后仍尝试的末尾同步。 */
} vireo_tcp_server_tls_close_step_info_t;

/** 主request/step首因优先于同步，再优先于队列；无提交回滚。 */
typedef struct vireo_tcp_server_tls_close_error {
    vireo_tcp_server_tls_close_stage_t stage; /**< 主失败阶段。 */
    vireo_tls_connection_error_t tls_error; /**< 主TLS原因。 */
    vireo_tcp_server_client_error_t client_error; /**< 原租约原因。 */
    vireo_clock_error_t clock_error; /**< 新采时原因。 */
    vireo_result_t sync_result; /**< 独立最终观察/MOD结果。 */
    vireo_tcp_server_tls_close_stage_t sync_stage; /**< 同步失败位置。 */
    vireo_tls_connection_error_t sync_tls_error; /**< 最终观察原因。 */
    vireo_connection_loop_error_t sync_loop_error; /**< 实际MOD原因。 */
    vireo_result_t queue_result; /**< 独立入队结果。 */
} vireo_tcp_server_tls_close_error_t;

/**
 * @brief 一次请求关闭并同步真实关注，不执行TLS网络
 *
 * @param[in,out] server
 *     非空TLS根，同Reactor串行，无同server其他阶段在途。
 * @param[in] client
 *     当前完整且绑定/loop_attached租约，仅调用期短借对象。
 * @param[in] timeout_ns
 *     正关闭总时长；checked加到新采时，涵盖排空/双向通知/尾部。
 * @param[out] out_info
 *     必需独立可写报告，每可写路径覆盖；requested提交后不回滚。
 * @param[out] error
 *     可空独立诊断，每可写路径覆盖。
 *
 * @retval VIREO_OK
 *     原request封口成功且最终关注/队列同步成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址、正时长或租约形状/所属池非法。
 * @retval VIREO_RESULT_RANGE
 *     租约槽索引越界。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空/旧租约、未绑定或未loop_attached。
 * @retval VIREO_RESULT_BUSY
 *     RAW、重入、未ESTABLISHED、未启用应用或已经request。
 * @retval VIREO_RESULT_OVERFLOW
 *     新采时与正时长的加法不可表示，尚未封口。
 * @retval VIREO_RESULT_IO
 *     原时钟/MOD失败或原应用I/O首错；读取独立诊断。
 * @retval VIREO_RESULT_PROTOCOL
 *     原应用协议首错，原request仅重现，不采时/封口。
 * @retval VIREO_RESULT_NO_MEMORY
 *     原应用缓存资源首错，本入口不分配。
 * @retval VIREO_RESULT_INTERNAL
 *     原观察/队列/报告不变量错误或原应用内部首错。
 *
 * @note 重复请求在采时前拒绝，不延长due。成功后禁止新enqueue及普通应用驱动。
 *     caller应先完成需响应业务；关闭尾部由caller peek/consume/分析，不自动handler。
 *     无分配/等待/native/释放；COMPLETE仍占资源。地址独立/错误队列/errno沿构造合同。
 *     同步失败以close_flow_refresh修复，不重放request；HUP/ERR仍可能在mask0时投递。
 */
vireo_result_t vireo_tcp_server_client_tls_close_request(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, uint64_t timeout_ns,
    vireo_tcp_server_tls_close_request_info_t *out_info, vireo_tcp_server_tls_close_error_t *error);

/**
 * @brief 有期限地驱动一个关闭客户，至多一次原生调用，再同步实际关注
 *
 * @param[in,out] server
 *     非空TLS根，同Reactor串行，无其他阶段在途。
 * @param[in] client
 *     当前完整且绑定/loop_attached租约，必须已request，终态可重现。
 * @param[in] max_bytes
 *     正字节预算，至少max(min(16384,读容量),min(16384,写容量))，
 *     所选原locked请求还须给足原长度；每次至多一个SSL操作。
 * @param[out] out_info
 *     必需独立报告，每可写路径覆盖，called/reported区分原生前拒绝。
 * @param[out] error
 *     可空独立主因/同步/入队诊断，每可写路径覆盖。
 *
 * @retval VIREO_OK
 *     WANT/NEED_CONSUME/进展/COMPLETE且最终同步成功，须读报告。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址/租约非法，或实际原生前SIGPIPE非SIG_IGN。
 * @retval VIREO_RESULT_RANGE
 *     槽索引、字节预算不足，或活跃时钟回退/所选locked请求不适配。
 * @retval VIREO_RESULT_BUSY
 *     RAW、重入、未ESTABLISHED/启用应用或尚未request。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空/旧租约、未绑定或未loop_attached。
 * @retval VIREO_RESULT_TIMEOUT
 *     固定总期限到达或重复缓存TIMEOUT，优先于信号/native。
 * @retval VIREO_RESULT_IO
 *     原采时/信号查询/SYSCALL/MOD或缓存I/O首错。
 * @retval VIREO_RESULT_PROTOCOL
 *     原TLS致命/裸EOF错误或重复缓存协议首错。
 * @retval VIREO_RESULT_NO_MEMORY
 *     原TLS明确malloc失败或缓存资源首错，本入口不分配。
 * @retval VIREO_RESULT_INTERNAL
 *     原观察/队列/子报告不变量、原生分类异常或缓存内部首错。
 *
 * @note 活跃阶段新采时；终态不采时，零native重现COMPLETE/缓存首错。
 *     尝试原step后即使失败仍最终同步，主错优先；主错不正常续排，仅MOD失败排恢复。
 *     wait映射真实READ/WRITE加RDHUP，NONE仅RDHUP且按resume续排；needs_consume/终态
 *     目标0。只mask变化才MOD；read_size/has_pending本身不入队，不吞尾部/调用handler。
 *     保持errno；资源/地址/SIGPIPE/库队列沿原TLS合同，不自动关闭fd或release。
 */
vireo_result_t vireo_tcp_server_client_tls_close_step(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, size_t max_bytes,
    vireo_tcp_server_tls_close_step_info_t *out_info, vireo_tcp_server_tls_close_error_t *error);

/**
 * @brief 纯刷新已请求客户的真实关闭关注及本地续调度
 *
 * @param[in,out] server
 *     非空TLS根，同Reactor串行，无其他阶段在途。
 * @param[in] client
 *     当前完整绑定/loop_attached租约，包括COMPLETE/FAILED。
 * @param[out] out_info
 *     必需独立报告，每可写路径覆盖；实际mask与各调用标记分开。
 * @param[out] error
 *     可空独立诊断，每可写路径覆盖。
 *
 * @retval VIREO_OK
 *     实际关注及续排同步成功，含FAILED成功清关注；不重现缓存首错。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址或租约形状/所属池非法。
 * @retval VIREO_RESULT_RANGE
 *     租约槽索引越界。
 * @retval VIREO_RESULT_BUSY
 *     RAW、重入、未ESTABLISHED/启用应用或尚未request。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空/旧租约、未绑定或未loop_attached。
 * @retval VIREO_RESULT_IO
 *     原公开MOD失败；读取sync_loop_error中原系统原因。
 * @retval VIREO_RESULT_INTERNAL
 *     原观察/队列或状态不变量异常，不代表TLS缓存首错。
 *
 * @note 外部consume后或MOD失败后使用；不采时/native/request/step/handler/释放。
 *     映射/去重规则沿close_step，MOD失败仍保旧mask并尝试一次恢复入队。
 *     mask0无法屏蔽内核无条件HUP/ERR，caller处理已投递事件/尾部及最终归还。
 *     保持errno，地址/资源/库错误队列沿构造合同，不修改固定due或重放数据。
 */
vireo_result_t vireo_tcp_server_client_tls_close_flow_refresh(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_tls_close_flow_info_t *out_info,
    vireo_tcp_server_tls_close_error_t *error);

/** TLS客户轮的数值副本；各预算只授予每客户一次，不随重排补领。 */
typedef struct vireo_tcp_server_tls_round_options {
    int timeout_ms; /**< 非负等待上限；有待办或due已到时实际为0。 */
    vireo_tcp_server_process_options_t process; /**< 请求/响应最大整帧字节。 */
    vireo_tcp_server_tls_drive_budget_t drive; /**< 原应用收/处理/发三预算。 */
    vireo_tcp_server_round_budget_t round; /**< 本轮客户上限，1..65535。 */
    size_t close_max_bytes; /**< 原关闭单步字节，至少两FIFO最小稳定请求的最大值。 */
} vireo_tcp_server_tls_round_options_t;

/** 本turn按真实状态选择的唯一协议阶段，不以事件方向代替原操作。 */
typedef enum vireo_tcp_server_tls_turn_path {
    VIREO_TCP_SERVER_TLS_TURN_NONE = 0, /**< 尚未分派，或lookup/观察失败。 */
    VIREO_TCP_SERVER_TLS_TURN_HANDSHAKE = 1, /**< 一次握手步骤或其缓存首错。 */
    VIREO_TCP_SERVER_TLS_TURN_APPLICATION = 2, /**< 原有界应用drive。 */
    VIREO_TCP_SERVER_TLS_TURN_CLOSE = 3 /**< 已请求关闭的一次step或终态。 */
} vireo_tcp_server_tls_turn_path_t;

/** 客户轮组合主阶段；不重排或压扁旧阶段诊断。 */
typedef enum vireo_tcp_server_tls_round_stage {
    VIREO_TCP_SERVER_TLS_ROUND_NONE = 0, /**< 成功或共同前置拒绝。 */
    VIREO_TCP_SERVER_TLS_ROUND_WAIT = 1, /**< 原扫描/采时/等待/停止观察，见wait_error。 */
    VIREO_TCP_SERVER_TLS_ROUND_QUEUE = 2, /**< 原FIFO不变量或撤取失败。 */
    VIREO_TCP_SERVER_TLS_ROUND_LOOKUP = 3, /**< 完整lease/绑定/公开TLS短借失败。 */
    VIREO_TCP_SERVER_TLS_ROUND_INSPECT = 4, /**< 分派公开状态观察或不变量失败。 */
    VIREO_TCP_SERVER_TLS_ROUND_HANDSHAKE = 5, /**< 原握手主/同步错误。 */
    VIREO_TCP_SERVER_TLS_ROUND_APPLICATION = 6, /**< 原应用主/同步/队列错误。 */
    VIREO_TCP_SERVER_TLS_ROUND_CLOSE = 7, /**< 原关闭主/同步/队列错误。 */
    VIREO_TCP_SERVER_TLS_ROUND_HANDOFF_QUEUE = 8 /**< 握手建立后应用交接排队失败。 */
} vireo_tcp_server_tls_round_stage_t;

/** 独立按值错误；未参与分支typed零，不保存owner/指针。 */
typedef struct vireo_tcp_server_tls_round_error {
    vireo_tcp_server_tls_round_stage_t stage; /**< 本次组合主阶段。 */
    vireo_connection_pool_lease_t client; /**< 失败客户；等待/共同拒绝时零。 */
    vireo_tcp_server_tls_error_t wait_error; /**< 原扫描/clock/wait完整原因。 */
    vireo_tcp_server_client_error_t client_error; /**< 分派lookup/绑定原原因。 */
    vireo_tls_connection_error_t tls_error; /**< 分派TLS公开观察原因。 */
    vireo_tcp_server_tls_error_t handshake_error; /**< 握手原主/同步/恢复原因。 */
    vireo_tcp_server_tls_application_error_t application_error; /**< 应用原主/次原因。 */
    vireo_tcp_server_tls_close_error_t close_error; /**< 关闭原主/次原因。 */
} vireo_tcp_server_tls_round_error_t;

/** 一个已撤取客户的事实；未执行阶段typed零，lease不保活资源。 */
typedef struct vireo_tcp_server_tls_turn_result {
    vireo_connection_pool_lease_t client; /**< 原FIFO撤取的完整身份。 */
    uint32_t events; /**< 该位置撤取前pending事件OR，允许0。 */
    vireo_tcp_server_tls_turn_path_t path; /**< 已实际选择的唯一阶段。 */
    vireo_result_t result; /**< 阶段或交接主要返回；OK可仍WANT。 */
    vireo_tcp_server_tls_handshake_info_t handshake; /**< HANDSHAKE原报告。 */
    vireo_tcp_server_tls_drive_info_t application; /**< APPLICATION原报告。 */
    vireo_tcp_server_tls_close_step_info_t close; /**< CLOSE原报告。 */
    vireo_tcp_server_tls_round_error_t error; /**< 当前失败turn的完整诊断。 */
} vireo_tcp_server_tls_turn_result_t;

/** 每可写路径提交实际已知事实；与旧poll selected前缀报告分离。 */
typedef struct vireo_tcp_server_tls_round_info {
    vireo_event_loop_run_info_t wait; /**< 原loop统计，失败/未调用逻辑零。 */
    bool wait_called; /**< 已进入loop，不代表成功。 */
    bool stopped; /**< 本次入口或wait后观察到停止。 */
    int effective_timeout_ms; /**< 实际计划非负等待，未计划时0。 */
    uint32_t listener_events; /**< 成功wait窗口监听OR，仅提示caller。 */
    size_t scanned_slots; /**< 前后扫描实际槽数，至多2N。 */
    size_t expired_clients; /**< 后扫描活跃到期客户数，含原已排者。 */
    bool has_deadline; /**< 前扫描存在活跃握手或关闭due。 */
    vireo_monotonic_ns_t nearest_deadline_ns; /**< has_deadline时有效的最近due。 */
    vireo_monotonic_ns_t before_wait_ns; /**< 成功前采时，结合wait_error判断。 */
    vireo_monotonic_ns_t after_wait_ns; /**< 成功后采时，0不是空时间哨兵。 */
    size_t queued_before_wait; /**< 队列核验后的入口Q。 */
    size_t queued_after_wait; /**< 后扫描结束或失败时实际Q，未撤取。 */
    size_t turn_count; /**< out_turns真实前缀，含首失败客户。 */
    size_t succeeded_count; /**< turn返回OK数。 */
    size_t failed_count; /**< 失败turn数，0或1。 */
    size_t remaining_count; /**< 返回时原FIFO项数，未核验时0。 */
} vireo_tcp_server_tls_round_info_t;

/**
 * @brief 等待一次并按真实TLS状态执行有界FIFO客户轮
 * @param[in,out] server 非空TLS根，已拥有绑定listener，同Reactor且无其他在途。
 * @param[in] options 非空数值副本；非负timeout、正预算及帧/固定容量兼容在wait前核验。
 * @param[in,out] wire_workspace 非空独立短借响应区，最多最大响应整帧前缀可变。
 * @param[in] workspace_capacity 工作区实际容量，至少process最大响应整帧。
 * @param[in] handler 非空有界非阻塞原同步handler，不保留借用或修改同server。
 * @param[in,out] context 可空caller短借，仅活到本调用返回。
 * @param[out] out_turns 必需独立数组，只写turn_count前缀，含首失败项，suffix保持。
 * @param[in] turn_capacity 正元素数1..65535，限制本轮访问客户数。
 * @param[out] out_info 必需独立报告，每可写路径覆盖，基本拒绝为typed零。
 * @param[out] error 可空独立诊断，每可写路径覆盖，原主/次原因保留。
 * @retval VIREO_OK 有限轮或协作停止；含WANT/预算/半帧/NEED_CONSUME，非协议完成承诺。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需地址为空、负timeout或原阶段信号策略拒绝。
 * @retval VIREO_RESULT_RANGE 帧/预算/数组容量不兼容，或原handler/阶段超界。
 * @retval VIREO_RESULT_BUSY RAW根、同根在途或原阶段BUSY。
 * @retval VIREO_RESULT_NOT_FOUND 缺owned/bound listener或原客户租约/绑定失效。
 * @retval VIREO_RESULT_IO 原wait/clock/TLS/MOD/handler失败，原诊断保留。
 * @retval VIREO_RESULT_PROTOCOL 原TLS或帧/handler协议错误。
 * @retval VIREO_RESULT_TIMEOUT 原握手/关闭due已到，或handler超时。
 * @retval VIREO_RESULT_NO_MEMORY 原TLS/handler资源失败；本编排不申请缓冲。
 * @retval VIREO_RESULT_OVERFLOW 原checked长度或handler溢出。
 * @retval VIREO_RESULT_CANCELLED 原handler协作取消。
 * @retval VIREO_RESULT_DATABASE 原handler依赖分类，不允许在Reactor阻塞DB。
 * @retval VIREO_RESULT_INTERNAL 队列/状态/依赖不变量异常。
 * @note K=min(后扫描Q,客户上限,结果容量)，逐头撤取，每客户每轮至多一个阶段。
 *     握手正常建立后尾排一次下轮应用；首错停止，未取客户仍在原FIFO，不回滚已提交进度。
 *     关闭只推进已请求的关闭；不自动accept/request/consume/handler尾部/release。
 * @note 共同拒绝不wait/native/handler/MOD且数组/workspace保持。wait流程失败无turn，Q的真实
 *     事件/到期增量保持；撤取后失败含一个失败turn，原MOD恢复待办不等于可安全重放业务。
 *     失败后caller先按原阶段诊断纯flow修复或显式处理/归还，不盲目再次run重放handler。
 * @note 基本/模式/预算拒绝先于停止；入口停止不等待/撤取，wait后停止保留Q且不开始turn。
 *     整轮在途保护含handler，跨线程仅原request_stop例外；观察允许、同根可变/递归/destroy BUSY。
 *     listener事件只提示，无自动监听错误策略；mask0不能屏蔽Linux无条件HUP/ERR。
 * @note 原两类期限扫描至多2N，非硬实时/抢占。地址须存活对齐独立不重叠，TLS信号/库队列
 *     沿原阶段；保持入口errno。结果只为值，无资源owner或长期借用，旧RAW自动策略不参与。
 */
vireo_result_t vireo_tcp_server_tls_run_once(vireo_tcp_server_t *server,
    vireo_tcp_server_tls_round_options_t const *options, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_tls_turn_result_t *out_turns, size_t turn_capacity,
    vireo_tcp_server_tls_round_info_t *out_info, vireo_tcp_server_tls_round_error_t *error);

/** 当前容量与实际监听开关；无持久策略或资源owner。 */
typedef struct vireo_tcp_server_tls_admission_info {
    bool connection_limited; /**< 当前客户已占满固定槽位，失败/关闭终态仍占名额。 */
    bool buffer_limited; /**< 原两FIFO容量余量不能再容纳一个固定pair。 */
    bool tls_resource_limited; /**< 新四固定区余量不能再容纳一个客户。 */
    bool sync_called; /**< 本次目标与实际不同，确已尝试一次监听set_read。 */
    bool listener_read_enabled; /**< 返回时实际已提交READ；MOD失败保持旧值。 */
} vireo_tcp_server_tls_admission_info_t;

/** 有限服务数值副本；客户轮和接入预算独立。 */
typedef struct vireo_tcp_server_tls_serve_options {
    vireo_tcp_server_tls_round_options_t round; /**< 原完整客户轮配置，timeout非负。 */
    vireo_tcp_server_admit_budget_t admit; /**< 原正accept数量/调用双预算。 */
} vireo_tcp_server_tls_serve_options_t;

/** 每可写路径提交；前后刷新helper调用与真正MOD分别观察。 */
typedef struct vireo_tcp_server_tls_serve_info {
    vireo_tcp_server_tls_round_info_t round; /**< 原客户轮事实；remaining_count是其返回时Q。 */
    vireo_tcp_server_tls_admit_info_t admission; /**< 原接入事实，含错误时已发布lease前缀。 */
    vireo_tcp_server_tls_admission_info_t pre_sync; /**< 前刷新事实，未调用逻辑零。 */
    vireo_tcp_server_tls_admission_info_t post_sync; /**< 后刷新事实，未调用逻辑零。 */
    bool pre_sync_called; /**< 已进入前刷新helper，不表示一定MOD。 */
    bool post_sync_called; /**< 已进入后刷新helper，不表示一定MOD。 */
    bool admission_called; /**< 已进入有限接入core，可能没有成功accept。 */
    bool stopped; /**< 入口、原round或接入前某个边界已观察stop，不表示资源已清理。 */
} vireo_tcp_server_tls_serve_info_t;

/** 服务主失败阶段；首主因不被后同步失败覆盖。 */
typedef enum vireo_tcp_server_tls_serve_stage {
    VIREO_TCP_SERVER_TLS_SERVE_NONE = 0, /**< 成功或常规前置拒绝。 */
    VIREO_TCP_SERVER_TLS_SERVE_PRE_SYNC = 1, /**< 前容量刷新失败。 */
    VIREO_TCP_SERVER_TLS_SERVE_ROUND = 2, /**< 原客户轮或前置队列不变量失败。 */
    VIREO_TCP_SERVER_TLS_SERVE_STOP = 3, /**< 入口或成功round后的停止观察失败。 */
    VIREO_TCP_SERVER_TLS_SERVE_LISTENER_EVENT = 4, /**< 本wait监听ERROR/HANGUP，原位在round报告。 */
    VIREO_TCP_SERVER_TLS_SERVE_ADMIT = 5, /**< 原有限TLS接入失败，前缀不撤回。 */
    VIREO_TCP_SERVER_TLS_SERVE_POST_SYNC = 6 /**< 此前成功，末尾容量刷新成为主错。 */
} vireo_tcp_server_tls_serve_stage_t;

/** 独立按值诊断；原客户阶段内主次原因与外层监听次因互不覆盖。 */
typedef struct vireo_tcp_server_tls_serve_error {
    vireo_tcp_server_tls_serve_stage_t stage; /**< 本次首主阶段。 */
    vireo_tcp_server_tls_round_error_t round_error; /**< 原客户轮完整原因。 */
    vireo_tcp_server_tls_error_t admission_error; /**< 原接入主因及首清理错。 */
    vireo_tcp_server_listener_error_t listener_error; /**< PRE/POST_SYNC主因的监听诊断。 */
    vireo_result_t sync_result; /**< 已有主因时末尾同步次错；未发生/成功均OK。 */
    vireo_tcp_server_listener_error_t sync_error; /**< sync_result对应完整原诊断。 */
} vireo_tcp_server_tls_serve_error_t;

/**
 * @brief 按三种固定容量刷新TLS监听READ，不接入或服务客户
 *
 * @param[in,out] server
 *     非空存活TLS根，已拥有绑定listener，同Reactor且无其他在途。
 * @param[out] out_info
 *     非空独立报告，每可写路径覆盖；前置/容量不变量拒绝typed零。
 * @param[out] error
 *     可空独立监听诊断，每可写路径覆盖；MOD失败保存UPDATE及原原因。
 *
 * @retval VIREO_OK
 *     实际READ与三容量目标一致，同值省MOD。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空。
 * @retval VIREO_RESULT_BUSY
 *     RAW根或同根可变阶段在途。
 * @retval VIREO_RESULT_NOT_FOUND
 *     缺owned/bound监听，或原MOD依赖拒绝。
 * @retval VIREO_RESULT_IO
 *     一次MOD失败，原实际开关保持。
 * @retval VIREO_RESULT_INTERNAL
 *     固定容量账不变量异常，或原依赖异常。
 *
 * @note 目标同时要求可用槽、原pair额度和TLS四区额度均容纳一个客户；只release退款。
 *     显式调用会覆盖手动READ暂停，不保存策略enabled；旧RAW admission_*快照不改义。
 *     不观察stop、不采时、不native/accept/handler、不改变队列或owner；stop后也可刷新。
 * @note 同值无系统调用；目标变化最多一次公开set_read，失败原errno保存在嵌套诊断。
 *     保持入口errno；地址须存活对齐独立不重叠，不在自有资源或errno内。无并发销毁、
 *     signal-handler或fork后未exec调用；跨线程仅原request_stop例外。
 */
vireo_result_t vireo_tcp_server_tls_admission_refresh(vireo_tcp_server_t *server,
    vireo_tcp_server_tls_admission_info_t *out_info, vireo_tcp_server_listener_error_t *error);

/**
 * @brief 一次TLS客户轮后有限接入，并在前后按真实固定容量同步监听
 *
 * @param[in,out] server
 *     非空存活TLS根，owned/bound监听，同Reactor且无其他在途。
 * @param[in] options
 *     非空独立数值副本；原round全部约束及正接入双预算在任何MOD/wait前核验。
 * @param[in,out] wire_workspace
 *     非空独立短借响应区，沿原round可修改最大响应整帧前缀。
 * @param[in] workspace_capacity
 *     实际字节数，至少options.round.process最大响应整帧。
 * @param[in] handler
 *     非空原有界非阻塞同步handler，不保留借用或修改同server。
 * @param[in,out] context
 *     可空caller短借handler上下文，仅到返回。
 * @param[out] out_turns
 *     独立数组，仅写out_info.round.turn_count前缀，含首失败项，suffix保持。
 * @param[in] turn_capacity
 *     数组正元素数1..65535，限制原客户K。
 * @param[in,out] out_clients
 *     独立新租约数组；min(client_capacity,max_accepts)潜在前缀入口全零。
 *     仅写admission.admission.admitted_count前缀，非OK也可能发布新租约。
 * @param[in] client_capacity
 *     数组正元素数1..65535，与max_accepts共同限制接入数。
 * @param[out] out_info
 *     非空独立报告，每可写路径覆盖；常规前置拒绝typed零，运行错误保实际事实。
 * @param[out] error
 *     可空独立主次诊断，每可写路径覆盖，未参与分支typed零。
 *
 * @retval VIREO_OK
 *     有限机会或停止；含WANT/预算/容量/WOULD_BLOCK停止，不承诺协议全部完成。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址、非负timeout、正接入预算/空租约不合法，或原阶段信号策略拒绝。
 * @retval VIREO_RESULT_RANGE
 *     数组/客户硬限、帧或稳定重试预算不兼容，或原handler范围错误。
 * @retval VIREO_RESULT_BUSY
 *     RAW/同根在途或原客户阶段BUSY。
 * @retval VIREO_RESULT_NOT_FOUND
 *     缺owned/bound监听或原租约/登记失效。
 * @retval VIREO_RESULT_IO
 *     原监听/等待/时钟/TLS/接入/handler失败，保原诊断。
 * @retval VIREO_RESULT_PROTOCOL
 *     原TLS、framing或handler协议错误。
 * @retval VIREO_RESULT_TIMEOUT
 *     原握手/关闭due或handler超时。
 * @retval VIREO_RESULT_NO_MEMORY
 *     原接入/TLS/handler申请失败，编排自身不申请缓冲。
 * @retval VIREO_RESULT_OVERFLOW
 *     原受检期限/长度或handler溢出。
 * @retval VIREO_RESULT_CANCELLED
 *     原handler协作取消。
 * @retval VIREO_RESULT_DATABASE
 *     原handler依赖分类，不允许在Reactor阻塞DB。
 * @retval VIREO_RESULT_INTERNAL
 *     原队列/容量/状态/依赖不变量异常。
 *
 * @note 全部参数校验→入口stop→前刷新→原round→停止/监听检查→有限admit→后刷新。
 *     新客户只在下一round握手，客户K与接入预算独立；无READ不accept，ERROR/HANGUP优先
 *     READ并报IO；round先失败时保其主因。监听事件仅取本次round报告，不用历史事件。
 * @note 参数/模式/预算拒绝不MOD/wait且数组/workspace保持；前置坏Q报告ROUND/QUEUE。
 *     入口停止不刷新/等待/撤取/接入。前刷新失败不立即重试；前刷新成功后任何执行错误或
 *     停止仍尝试后刷新一次。已有主错时保主返回与原typed原因，后错只写sync_result/error；
 *     无主错时后错为POST_SYNC。已处理turn/发布lease不回滚，suffix保持。
 * @note 原round.remaining_count是客户轮返回时Q，不含随后接入；不自动关闭请求/消费尾部/
 *     归还/continuous run。失败先查两前缀并纯flow/监听刷新或处理客户，不盲重放业务。
 *     显式调用按容量覆盖手动READ；stop不关闭监听或资源，后刷新仍只依据容量。
 * @note 成功round后接入前再观察stop；handler请求stop可阻止接入，晚于此边界的请求允许
 *     已开始有限批次完成，无抢占承诺。整次含handler/监听依赖保持在途保护，同根可变/
 *     递归/destroy BUSY；观察允许，跨线程仅原request_stop例外。
 * @note 地址/errno/信号/库队列沿原TLS合同；保持入口errno。三容量不是RSS/限流/硬实时
 *     保证；暂停READ不能屏蔽Linux无条件HUP/ERR。所有输出仅值，不授予资源owner或保活。
 */
vireo_result_t vireo_tcp_server_tls_serve_once(vireo_tcp_server_t *server,
    vireo_tcp_server_tls_serve_options_t const *options, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_tls_turn_result_t *out_turns, size_t turn_capacity,
    vireo_connection_pool_lease_t *out_clients, size_t client_capacity,
    vireo_tcp_server_tls_serve_info_t *out_info, vireo_tcp_server_tls_serve_error_t *error);

#endif /* VIREO_NET_TCP_SERVER_TLS_H */
