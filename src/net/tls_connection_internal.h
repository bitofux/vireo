/*
- PROJECT : VIREO
- FILE    : tls_connection_internal.h
- AUTHOR  : bitofux
- DATE    : 2026-10-17
- BRIEF   : 此模块负责：
- -- 034同target内逐连接资源布局与逐对象故障缝，不作为下游合同
 */
#ifndef VIREO_NET_TLS_CONNECTION_INTERNAL_H
#define VIREO_NET_TLS_CONNECTION_INTERNAL_H

#include <openssl/ssl.h>
#include <vireo/base/buffer.h>
#include <vireo/net/tls_connection.h>

/** 完整表按值保存；回调/context存活到销毁，不重入/修改owner或输入。
 *  查询遵守真实0/-1或flags/-1与errno，资源返回真实可释放对象或NULL。
 *  create_native使用给定context并取得SSL内部引用；create_bio必须BIO_NOCLOSE。
 */
typedef struct vireo_tls_connection_ops {
    void *context; /**< 借用own夹具；生产为NULL。 */
    void *(*allocate)(void *context, size_t bytes); /**< 基本对齐的唯一正字节区域或NULL。 */
    void (*deallocate)(void *context, void *pointer); /**< 配对释放，无失败返回。 */
    int (*get_flags)(void *context, int fd, int command); /**< 只读F_GETFL/F_GETFD。 */
    int (*socket_type)(void *context, int fd, int *out_type); /**< SO_TYPE，成功才写值。 */
    int (*peer_connected)(void *context, int fd); /**< getpeername，只检查已连接。 */
    SSL *(*create_native)(void *context, SSL_CTX *native_context); /**< 新SSL或NULL。 */
    BIO *(*create_bio)(void *context, int borrowed_fd); /**< 新socket BIO，永不关闭fd。 */
} vireo_tls_connection_ops_t;

/** 单次短借的握手own缝；分类必须紧邻同线程原生调用，无中间OpenSSL操作。
 *  signal查询只读且成功才写bool；回调不重入/改owner，不用于业务backend。
 */
typedef struct vireo_tls_handshake_ops {
    void *context; /**< 只借到当前step返回，不保存进对象。 */
    int (*sigpipe_ignored)(void *context, bool *out_ignored); /**< 查询0/-1及errno。 */
    int (*do_handshake)(void *context, SSL *native); /**< 原生1成功或<=0待分类。 */
    int (*get_error)(void *context, SSL *native, int returned); /**< 紧邻SSL_get_error分类。 */
} vireo_tls_handshake_ops_t;

/** 配置own故障缝按值保存，全部资源回调/context存活到destroy；不修改native后失败。
 * buffer只可用公开create/destroy，资源失败必须保持空owner；prepare不执行网络。
 */
typedef struct vireo_tls_io_config_ops {
    void *context;
    void *(*allocate)(void *context, size_t bytes);
    void (*deallocate)(void *context, void *pointer);
    vireo_result_t (*buffer_create)(void *context, size_t size, vireo_buffer_t **out);
    void (*buffer_destroy)(void *context, vireo_buffer_t **owner);
    bool (*prepare)(void *context, SSL *native);
} vireo_tls_io_config_ops_t;

/** 原生own缝只借到一次drive返回；get_error必须紧邻相应read/write调用。 */
typedef struct vireo_tls_io_ops {
    void *context;
    int (*sigpipe_ignored)(void *context, bool *out_ignored);
    int (*read_ex)(void *context, SSL *native, void *data, size_t size, size_t *out_size);
    int (*write_ex)(void *context, SSL *native, void const *data, size_t size, size_t *out_size);
    int (*get_error)(void *context, SSL *native, int returned);
} vireo_tls_io_ops_t;

/** 关闭own缝仅本次借用，内嵌I/O表沿原紧邻分类合同；不作为业务backend。 */
typedef struct vireo_tls_close_ops {
    vireo_tls_io_ops_t io;
    int (*shutdown)(void *context, SSL *native); /**< 原始0/1正常，负数才get_error。 */
} vireo_tls_close_ops_t;

/** 关闭值状态无新增资源；重试/EOF仍复用唯一io存储。 */
typedef struct vireo_tls_close_storage {
    vireo_tls_close_state_t state; /**< request后独立推进，终态永久。 */
    vireo_monotonic_ns_t deadline_ns; /**< request固定的关闭总期限。 */
    vireo_monotonic_ns_t last_now_ns; /**< request或最近正常/到期提交的时间。 */
    bool local_notify_sent; /**< 仅原生shutdown 0/1确认，不信SENT位。 */
    vireo_tls_io_wait_t shutdown_wait; /**< 原shutdown WANT重试优先，不与尾部read混用。 */
    vireo_result_t failure_result; /**< 仅关闭FAILED非OK，首错不覆盖。 */
    vireo_tls_connection_error_t failure_error; /**< 关闭首诊断独立值；不借原因字符串。 */
} vireo_tls_close_storage_t;

/** 单连接固定资源及值状态；prepare/configure原子发布，release逆序释放，DISABLED全零。 */
typedef struct vireo_tls_io_storage {
    vireo_tls_io_state_t state; /**< PREPARED有资源但禁业务；握手成功才OPEN，不覆盖握手历史。 */
    vireo_tls_io_options_t options; /**< 配置值复制。 */
    size_t buffer_bytes; /**< 四个字节资源请求和。 */
    vireo_buffer_t *read_buffer; /**< 唯一公开buffer owner。 */
    vireo_buffer_t *write_buffer; /**< 唯一公开buffer owner，前缀确认才consume。 */
    uint8_t *read_scratch; /**< 固定16KiB，跨read WANT稳定；确认复制/EOF/终态后清零。 */
    uint8_t *write_scratch; /**< 固定16KiB，跨write WANT内容稳定；确认消费/终态后清零。 */
    vireo_tls_io_config_ops_t resources; /**< 保活配对资源回调/context。 */
    size_t read_retry_bytes; /**< 未完成原请求长度，无请求0。 */
    size_t write_retry_bytes; /**< 未完成原快照长度，无请求0。 */
    vireo_tls_io_wait_t read_wait; /**< 最新read WANT，无请求NONE。 */
    vireo_tls_io_wait_t write_wait; /**< 最新write WANT，无请求NONE。 */
    bool read_eof; /**< read ZERO_RETURN或shutdown返回1确认真实对端通知。 */
    bool read_pressure; /**< 仅flow_refresh更新的迟滞锁存。 */
    bool write_pressure; /**< 同上。 */
    bool resume_read; /**< read预算停止，下一次WANT/EOF/fatal清除。 */
    bool resume_write; /**< write预算停止，下一次WANT/空/fatal清除。 */
    vireo_result_t failure_result; /**< 独立应用首错。 */
    vireo_tls_connection_error_t failure_error; /**< 独立应用首诊断。 */
} vireo_tls_io_storage_t;

struct vireo_tls_connection {
    vireo_tls_io_storage_t io; /**< 固定应用资源，未配置零态。 */
    vireo_tls_close_storage_t close; /**< 同owner关闭值状态，create整体零初始化。 */
    SSL *native; /**< 唯一拥有，SSL_free一并释放BIO及native context引用。 */
    int borrowed_fd; /**< 仅借用的数值；不是身份/代际，也不负责close。 */
    size_t max_wrapper_bytes; /**< 原包装预算，不含第三方申请。 */
    vireo_tls_connection_ops_t ops; /**< 值复制；借用context由测试caller保活。 */
    vireo_tls_handshake_state_t state; /**< create初态，step单调推进至终态。 */
    vireo_tls_handshake_wait_t wait; /**< 最近WANT方向，初态/终态NONE。 */
    bool handshake_native_attempted; /**< 确实调用过原生握手；首次前超时保持false。 */
    bool deadline_armed; /**< 一次固定配置，初态false，终态保留。 */
    vireo_monotonic_ns_t deadline_ns; /**< 同域有限绝对期限，未arm为0，不续期。 */
    vireo_monotonic_ns_t last_now_ns; /**< arm或最近提交的timed step时间，原生前拒绝不改。 */
    vireo_result_t failure_result; /**< 首个致命结果，仅FAILED非OK。 */
    vireo_tls_connection_error_t failure_error; /**< 首诊断独立值，终态不再覆盖。 */
};

/**
 * @brief 用完整own操作表执行同一创建核心，验证本层系统/资源失败
 *
 * @param[in] context
 *     公共服务器context短借合同。
 * @param[in] options
 *     公共显式包装预算。
 * @param[in] borrowed_fd
 *     公共socket借用合同。
 * @param[in,out] out_connection
 *     公共独立空owner。
 * @param[out] error
 *     公共可空独立诊断。
 * @param[in] ops
 *     完整表，仅创建调用短借，表按值复制；回调/context保活至销毁。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     表为空或缺少回调，其余离散结果沿公共创建合同。
 * @retval VIREO_OK
 *     完整发布同一生产布局和生命周期的对象。
 *
 * @note 保持errno；只供034同target内测试，不作为公共可插拔backend。
 */
vireo_result_t vireo_tls_connection_create_with_ops(vireo_tls_context_t const *context,
    vireo_tls_connection_options_t const *options, int borrowed_fd,
    vireo_tls_connection_t **out_connection, vireo_tls_connection_error_t *error,
    vireo_tls_connection_ops_t const *ops);

/**
 * @brief 用短借own缝验证同一握手核心，原生前拒绝无输出提交
 *
 * @param[in,out] connection
 *     沿公共存活串行对象合同。
 * @param[out] out_info
 *     沿公共独立步进报告合同。
 * @param[out] error
 *     沿公共可空诊断合同。
 * @param[in] ops
 *     必需完整表，函数/context只保活到本次返回，不保存。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     表为空或缺回调，其他分类/状态后置沿公共step。
 * @retval VIREO_OK
 *     同公共正常等待或握手完成。
 *
 * @note 只供034 own测试；不授跨核心私有布局或全局故障注入能力。
 */
vireo_result_t vireo_tls_connection_handshake_with_ops(vireo_tls_connection_t *connection,
    vireo_tls_handshake_info_t *out_info, vireo_tls_connection_error_t *error,
    vireo_tls_handshake_ops_t const *ops);

/** 同step_at核心，ops仅本次借用；到期仍提交报告但不调用任何ops。
 * 完整表先验验证，不能用缺回调表绕过基本参数规则；仅034 own测试。
 */
vireo_result_t vireo_tls_connection_handshake_at_with_ops(vireo_tls_connection_t *connection,
    vireo_monotonic_ns_t now, vireo_tls_handshake_info_t *out_info,
    vireo_tls_connection_error_t *error, vireo_tls_handshake_ops_t const *ops);

/**
 * @brief 清两块自有暂存，允许部分构造；不改FIFO或数值快照
 * @param[in,out] io 非空独占存活存储；每个非空scratch须指向完整16KiB自有区。
 * @note 仅资源初始化/释放或不再重试的终态调用；不得对活跃WANT调用。保持errno。
 */
void vireo_tls_io_clear_scratch(vireo_tls_io_storage_t *io);

/** 释放已配置或未发布候选资源；无网络，owner均清空，资源表保持到释放结束。 */
void vireo_tls_io_release(vireo_tls_io_storage_t *io);
/** 与公共configure同核；完整资源表先验检查，所有失败回滚且不发布。 */
vireo_result_t vireo_tls_connection_io_configure_with_ops(vireo_tls_connection_t *connection,
    vireo_tls_io_options_t const *options, vireo_tls_connection_error_t *error,
    vireo_tls_io_config_ops_t const *ops);
/** 与公共prepare同核；仅本模块完整资源故障表，回调/context沿configure保活规则。 */
vireo_result_t vireo_tls_connection_io_prepare_with_ops(vireo_tls_connection_t *connection,
    vireo_tls_io_options_t const *options, vireo_tls_connection_error_t *error,
    vireo_tls_io_config_ops_t const *ops);
/** 与公共receive/send同核；writing选择原操作，ops仅本次借用。 */
vireo_result_t vireo_tls_connection_io_with_ops(vireo_tls_connection_t *connection,
    vireo_tls_io_budget_t const *budget, vireo_tls_io_progress_t *out_progress,
    vireo_tls_connection_error_t *error, bool writing, vireo_tls_io_ops_t const *ops);

/** 生产原生表只读共享，关闭复用同一读写/信号/分类实现，不保存caller地址。 */
extern vireo_tls_io_ops_t const vireo_tls_io_native_ops;
/** 同收发核心的关闭专用入口：仅同target关闭驱动调用，跳过公开门禁和普通水位。
 * 预算/稳定重试/信号/分类/缓冲提交与原核心一致，ops仅本次借用。
 */
vireo_result_t vireo_tls_connection_io_closing_with_ops(vireo_tls_connection_t *connection,
    vireo_tls_io_budget_t const *budget, vireo_tls_io_progress_t *out_progress,
    vireo_tls_connection_error_t *error, bool writing, vireo_tls_io_ops_t const *ops);
/** 与公共关闭单步同核；完整ops短借，终态/到期不得调用回调。 */
vireo_result_t vireo_tls_connection_close_with_ops(vireo_tls_connection_t *connection,
    vireo_monotonic_ns_t now, size_t max_bytes, vireo_tls_close_progress_t *out_progress,
    vireo_tls_connection_error_t *error, vireo_tls_close_ops_t const *ops);

#endif
