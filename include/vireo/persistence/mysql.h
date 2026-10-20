/* MySQL 8.0资源边界；公共头不泄露原生驱动或pthread类型。 */
#ifndef VIREO_PERSISTENCE_MYSQL_H
#define VIREO_PERSISTENCE_MYSQL_H

#include <stdint.h>
#include <vireo/base/result.h>

/** @brief Unix pathname socket的最大字节数，不计NUL。 */
#define VIREO_MYSQL_SOCKET_MAX 107
/** @brief 显式账号最大字节数，不计NUL。 */
#define VIREO_MYSQL_USERNAME_MAX 128
/** @brief 显式密码最大字节数，不计NUL，允许空字符串。 */
#define VIREO_MYSQL_PASSWORD_MAX 1024
/** @brief 显式数据库名最大字节数，不计NUL。 */
#define VIREO_MYSQL_DATABASE_MAX 256
/** @brief 各原生阶段等待的最大秒数，不是整个open硬总期限。 */
#define VIREO_MYSQL_TIMEOUT_MAX UINT32_C(3600)

/** @brief 唯一进程资源根；启动/结束管理外部串行，只允许一个成功生命周期。 */
typedef struct vireo_mysql_runtime vireo_mysql_runtime_t;
/** @brief 当前OS线程独占登记，不得跨线程传递，退出前须detach。 */
typedef struct vireo_mysql_thread vireo_mysql_thread_t;
/** @brief 独立连接唯一owner可同步交接；池内连接只允许租借线程在租期内短借。 */
typedef struct vireo_mysql_connection vireo_mysql_connection_t;

/** @brief 失败发生阶段，无SQL操作码/原始错误文本。 */
typedef enum vireo_mysql_stage {
    VIREO_MYSQL_STAGE_NONE = 0, /**< 无诊断阶段。 */
    VIREO_MYSQL_STAGE_SIGNAL_POLICY, /**< 读取/核对应用SIGPIPE策略。 */
    VIREO_MYSQL_STAGE_ALLOCATE, /**< wrapper申请。 */
    VIREO_MYSQL_STAGE_LIBRARY_INIT, /**< 原生进程库初始化。 */
    VIREO_MYSQL_STAGE_THREAD_INIT, /**< 原生当前线程初始化。 */
    VIREO_MYSQL_STAGE_NATIVE_INIT, /**< 原生连接handle申请。 */
    VIREO_MYSQL_STAGE_OPTIONS, /**< 原生连接选项。 */
    VIREO_MYSQL_STAGE_CONNECT, /**< 原生握手及选择目标库。 */
    VIREO_MYSQL_STAGE_SESSION_SETUP, /**< 固定会话基线设置。 */
    VIREO_MYSQL_STAGE_SESSION_VERIFY, /**< 会话基线及8.0版本核验。 */
    VIREO_MYSQL_STAGE_STATEMENT_INIT, /**< 原生语句申请。 */
    VIREO_MYSQL_STAGE_STATEMENT_PREPARE, /**< SQL预处理。 */
    VIREO_MYSQL_STAGE_STATEMENT_BIND, /**< 自有参数/结果绑定。 */
    VIREO_MYSQL_STAGE_STATEMENT_EXECUTE, /**< 单次原生执行。 */
    VIREO_MYSQL_STAGE_STATEMENT_METADATA, /**< 实际列元数据核验。 */
    VIREO_MYSQL_STAGE_STATEMENT_FETCH, /**< 当前行读取。 */
    VIREO_MYSQL_STAGE_STATEMENT_RESET, /**< 结果释放/重置。 */
    VIREO_MYSQL_STAGE_STATEMENT_CLOSE, /**< 语句close，owner仍消耗。 */
    VIREO_MYSQL_STAGE_CONNECTION_RESET /**< 池归还原生reset失败；旧值前缀保持。 */
} vireo_mysql_stage_t;

/** @brief open短借的显式选项；字符串须在上限+1可读范围内NUL终止。 */
typedef struct vireo_mysql_connection_options {
    const char *unix_socket; /**< 以/起始，1..107字节，无TCP/抽象socket回退。 */
    const char *username; /**< 非NULL，1..128字节。 */
    const char *password; /**< 非NULL，0..1024字节，不支持内嵌NUL。 */
    const char *database; /**< 非NULL，1..256字节，作为原生参数传递而非拼SQL。 */
    uint32_t connect_timeout_seconds; /**< 连接阶段等待，1..3600秒。 */
    uint32_t read_timeout_seconds; /**< 读取阶段等待，1..3600秒。 */
    uint32_t write_timeout_seconds; /**< 写入阶段等待，1..3600秒。 */
} vireo_mysql_connection_options_t;

/** @brief caller拥有的无秘密诊断；每次factory调用先重置。 */
typedef struct vireo_mysql_error {
    vireo_mysql_stage_t stage; /**< 实际失败阶段，无阶段时NONE。 */
    int system_error; /**< 仅POSIX检查失败时实际errno，其余0。 */
    uint32_t mysql_code; /**< 可用的真实驱动错误码，其余0。 */
    char sqlstate[6]; /**< 原生5字节加NUL；无可用原生错误时全零。 */
} vireo_mysql_error_t;

/** @brief 建连时保存的值快照，inspect无I/O，不是健康检查。 */
typedef struct vireo_mysql_connection_info {
    uint32_t server_version; /**< 8.0数字版本，例如80046。 */
    uint64_t connection_id; /**< 服务端连接ID，非OS线程/业务身份。 */
} vireo_mysql_connection_info_t;

/**
 * @brief 在workers创建前串行创建唯一进程资源根。
 * @param[out] out_runtime 必需owner地址，原值须NULL；成功才发布。
 * @param[out] error 可选诊断，每次调用重置；无错误文本/凭据。
 * @retval VIREO_OK 已初始化库并归一化隐式线程状态，creator也须显式attach。
 * @retval VIREO_RESULT_INVALID_ARGUMENT NULL/非空owner或SIGPIPE未预先SIG_IGN。
 * @retval VIREO_RESULT_BUSY 已有ACTIVE runtime。
 * @retval VIREO_RESULT_CANCELLED 已结束或原生库初始化失败的终态。
 * @retval VIREO_RESULT_NO_MEMORY wrapper申请失败，可修正后重试。
 * @retval VIREO_RESULT_IO sigaction检查失败，诊断保存实际errno。
 * @retval VIREO_RESULT_DATABASE 原生库初始化失败，同进程不再尝试。
 * @note 保持errno；可能分配/阻塞，不用于Reactor热路径。应用统一信号策略，
 *       本模块只读核对；首次原生init可能影响SIGPIPE。不混用其他库全局init/end。
 *       所有API地址须存活、对齐、互不覆盖且不指向errno；指针副本仅借用。
 */
vireo_result_t vireo_mysql_runtime_create(vireo_mysql_runtime_t **out_runtime,
    vireo_mysql_error_t *error);

/**
 * @brief 全部workers join、所有子资源释放后由creator串行结束库并清owner。
 * @param[in,out] runtime 必需owner地址；空owner幂等OK。
 * @retval VIREO_OK 已结束，或原本为空。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 地址NULL或非creator线程。
 * @retval VIREO_RESULT_BUSY 仍有guard/连接/池（含构造中，全空池仍保活），owner保持。
 * @note 不得与任何操作重叠；计数不替代同步/存活地址前置。保持errno，无自动清子资源。
 */
vireo_result_t vireo_mysql_runtime_destroy(vireo_mysql_runtime_t **runtime);

/**
 * @brief 在当前OS线程登记原生线程状态，每线程最多一个live guard。
 * @param[in] runtime 必需存活runtime，管理方保证不会并发销毁。
 * @param[out] out_thread 必需NULL owner地址，成功才发布。
 * @param[out] error 可选，每次调用重置。
 * @retval VIREO_OK 当前线程登记成功，必须由该线程detach。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需地址NULL或owner非空。
 * @retval VIREO_RESULT_BUSY 本线程已有guard。
 * @retval VIREO_RESULT_OVERFLOW 子资源计数无法表示。
 * @retval VIREO_RESULT_NO_MEMORY wrapper申请失败。
 * @retval VIREO_RESULT_DATABASE 原生thread_init失败。
 * @note 不同线程可并行attach/detach；保持errno，可能分配，无TLS析构/取消hook。
 */
vireo_result_t vireo_mysql_thread_attach(vireo_mysql_runtime_t *runtime,
    vireo_mysql_thread_t **out_thread, vireo_mysql_error_t *error);

/**
 * @brief 结束当前线程原生状态、释放guard并清owner。
 * @param[in,out] thread 必需owner地址，空owner幂等OK。
 * @retval VIREO_OK 已解除登记；仍活独立连接须已同步交接或以后由其他guard接管；池租约须先同线程归还。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 地址NULL或guard不属于当前线程。
 * @note 保持errno；不关闭连接，它独立pin住runtime；线程退出前必须显式调用。
 */
vireo_result_t vireo_mysql_thread_detach(vireo_mysql_thread_t **thread);

/**
 * @brief 打开显式Unix socket连接，设置并核验utf8mb4/UTC/strict/InnoDB/autocommit。
 * @param[in] thread 必需当前线程有效guard。
 * @param[in] options 必需显式选项，短借至返回；wrapper不保存凭据地址。
 * @param[out] out_connection 必需NULL owner地址，成功才发布完整连接。
 * @param[out] error 可选，每次调用重置，驱动诊断在close前复制。
 * @retval VIREO_OK MySQL客户端和服务端均8.0系列，基线已核。
 * @retval VIREO_RESULT_INVALID_ARGUMENT NULL/非空owner/错guard/空必需字符串/相对socket/零超时。
 * @retval VIREO_RESULT_RANGE 字符串或超时超过公共上限。
 * @retval VIREO_RESULT_OVERFLOW 连接计数无法表示。
 * @retval VIREO_RESULT_NO_MEMORY wrapper或原生handle申请失败。
 * @retval VIREO_RESULT_DATABASE 原生options/connect/session或版本核验失败。
 * @note 保持errno；失败不发布owner且全部回滚。不读取默认配置/环境凭据，不启用
 *       multi-statements/local-infile/自动重连。固定内部SQL，不提供业务SQL/事务。
 *       阶段超时不保证open硬总期限；可能阻塞，不在Reactor热路径运行。
 *       原生驱动可能保留密码副本至close，不保证所有秘密内存擦除。
 */
vireo_result_t vireo_mysql_connection_open(vireo_mysql_thread_t *thread,
    const vireo_mysql_connection_options_t *options,
    vireo_mysql_connection_t **out_connection, vireo_mysql_error_t *error);

/**
 * @brief 复制建连快照，无原生I/O或实时健康保证。
 * @param[in] thread 必需当前线程有效guard，须与connection同runtime。
 * @param[in] connection 必需存活连接，caller排他访问或外部同步交接后访问。
 * @param[out] out_info 必需独占输出；失败保持。
 * @retval VIREO_OK 快照完整复制。
 * @retval VIREO_RESULT_INVALID_ARGUMENT NULL/错线程guard/不同runtime。
 * @note 保持errno；独立connection不永久绑定创建线程；池连接要求有效租期及租借线程，guard不可交接。
 */
vireo_result_t vireo_mysql_connection_inspect(vireo_mysql_thread_t *thread,
    const vireo_mysql_connection_t *connection, vireo_mysql_connection_info_t *out_info);

/**
 * @brief 在当前有效guard下关闭原生连接、释放wrapper并清owner。
 * @param[in] thread 非空连接必需本线程同runtime guard；空连接允许NULL。
 * @param[in,out] connection 必需owner地址，空owner幂等OK。
 * @retval VIREO_OK 已关闭或原本为空。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 地址NULL/非空连接缺guard或错线程/runtime。
 * @retval VIREO_RESULT_BUSY 仍有live statement或连接属于池，owner保持；池连接只能经lease归还。
 * @note 所有在途访问/借用须结束；唯一owner只能在明确同步后转移。保持errno，
 *       可能阻塞，关闭后指针副本不得再用；不自动重试/重连或清理其他资源。
 */
vireo_result_t vireo_mysql_connection_destroy(vireo_mysql_thread_t *thread,
    vireo_mysql_connection_t **connection);

#endif
