/*
 * PROJECT : VIREO
 * FILE    : log.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-01
 * BRIEF   : 此模块负责：
 * -- 定义日志 record、UTC 显示时间和字节借用合同
 * -- 将 record 转为有界、完整、已转义的单行记录
 * -- 创建和消费拥有目录、file 与 stderr 副本的 opaque logger
 * -- 串行化同步事件写入，显式报告 sink 失败且不隐式重试
 * -- 显式同步 file 数据，在受控目录内执行单归档轮转
 */
#ifndef VIREO_BASE_LOG_H
#define VIREO_BASE_LOG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <vireo/base/result.h>

/** module 原始字节上限；不是转义后的长度。 */
#define VIREO_LOG_MAX_MODULE_SIZE ((size_t)64)
/** request_id 和 task_id 各自的原始字节上限。 */
#define VIREO_LOG_MAX_ID_SIZE ((size_t)128)
/** message 原始字节上限；超长返回 RANGE，不截断。 */
#define VIREO_LOG_MAX_MESSAGE_SIZE ((size_t)4096)
/** 完整行的字节硬上限，包含末尾 LF，不包含 C NUL。 */
#define VIREO_LOG_MAX_LINE_SIZE ((size_t)32768)

/** 自有日志目录容量，含 NUL；与 config 的目录容量兼容。 */
#define VIREO_LOG_DIRECTORY_CAPACITY ((size_t)1024)
/** file 启用时阈值范围为 1 MiB..1 GiB；下一完整行超过阈值才在写前轮转。 */
#define VIREO_LOG_MIN_FILE_SIZE_BYTES UINT64_C(1048576)
#define VIREO_LOG_MAX_FILE_SIZE_BYTES UINT64_C(1073741824)
/** 受控目录内固定的文件名；不接受 record 派生的路径分量。 */
#define VIREO_LOG_FILE_NAME "vireo.log"
/** 唯一归档名；再次轮转会替换合规的旧归档，不保留更早历史。 */
#define VIREO_LOG_ARCHIVE_NAME "vireo.log.1"

/** 唯一拥有型资源容器；布局非公共 ABI，销毁需要外部停止所有使用。 */
typedef struct vireo_log vireo_log_t;

/** 创建输入，整个调用期间稳定；成功后不再借用本对象或 directory。 */
typedef struct vireo_log_options {
    char const *directory;        /**< NULL 禁用 file，否则非空绝对目录，最多 1023 字节。 */
    bool to_stderr;                /**< 复制 create 当时的 stderr，logger 只关闭自己的副本。 */
    uint64_t max_file_size_bytes;  /**< file 启用时受上述阈值范围约束；否则忽略。 */
} vireo_log_options_t;

/** 按值诊断的资源类别；不是 wire 编号。 */
typedef enum vireo_log_sink {
    VIREO_LOG_SINK_NONE = 0,
    VIREO_LOG_SINK_FILE = 1,       /**< 包括受控目录及其中的 file。 */
    VIREO_LOG_SINK_STDERR = 2,     /**< logger 拥有的 stderr 副本，不是原 fd 2。 */
} vireo_log_sink_t;

/** 失败阶段；旧值保持，新增阶段只对应已经实现的操作。 */
typedef enum vireo_log_stage {
    VIREO_LOG_STAGE_NONE = 0,
    VIREO_LOG_STAGE_VALIDATE = 1,
    VIREO_LOG_STAGE_ALLOCATE = 2,
    VIREO_LOG_STAGE_DUP_STDERR = 3,
    VIREO_LOG_STAGE_CHECK_STDERR = 4,
    VIREO_LOG_STAGE_OPEN_DIRECTORY = 5,
    VIREO_LOG_STAGE_OPEN_FILE = 6,
    VIREO_LOG_STAGE_CHECK_FILE = 7,
    VIREO_LOG_STAGE_SYNC_FILE = 8,
    VIREO_LOG_STAGE_CLOSE_FILE = 9,
    VIREO_LOG_STAGE_CLOSE_STDERR = 10,
    VIREO_LOG_STAGE_CLOSE_DIRECTORY = 11,
    VIREO_LOG_STAGE_INIT_MUTEX = 12,     /**< 发布前创建对象锁。 */
    VIREO_LOG_STAGE_DESTROY_MUTEX = 13,  /**< 外部 quiesce 后销毁对象锁。 */
    VIREO_LOG_STAGE_LOCK = 14,           /**< 尚未开始处理该事件。 */
    VIREO_LOG_STAGE_UNLOCK = 15,         /**< 已执行处理，输出不能回滚。 */
    VIREO_LOG_STAGE_CLOCK = 16,          /**< 墙上时间获取或 UTC 转换。 */
    VIREO_LOG_STAGE_THREAD_ID = 17,      /**< Linux 调用线程身份。 */
    VIREO_LOG_STAGE_FORMAT = 18,         /**< 完整内存行生成，尚未写 sink。 */
    VIREO_LOG_STAGE_WRITE = 19,          /**< 某 sink 未完整接受一行。 */
    VIREO_LOG_STAGE_FILE_SIZE = 20,      /**< 当前 file 的大小或属性无法安全使用。 */
    VIREO_LOG_STAGE_CHECK_CURRENT_ENTRY = 21, /**< 轮转源目录项与已打开 file 不匹配。 */
    VIREO_LOG_STAGE_CHECK_ARCHIVE = 22,  /**< 归档目录项不存在以外的错误或不合规属性。 */
    VIREO_LOG_STAGE_RENAME_FILE = 23,    /**< 当前文件改名为单归档。 */
    VIREO_LOG_STAGE_OPEN_NEW_FILE = 24,  /**< 改名后排他创建新当前文件。 */
    VIREO_LOG_STAGE_CHECK_NEW_FILE = 25, /**< 新 file 获取后、所有权交接前检查。 */
    VIREO_LOG_STAGE_CLOSE_OLD_FILE = 26, /**< 已交接新 fd，消费旧 fd 失败。 */
} vireo_log_stage_t;

/** 诊断由调用者拥有，无内部指针；不冻结 padding 或序列化布局。 */
typedef struct vireo_log_error {
    vireo_log_sink_t sink;    /**< 成功为 NONE；失败为最先观察到错误的资源。 */
    vireo_log_stage_t stage;  /**< 成功为 NONE；失败为实际阶段。 */
    int system_errno;        /**< errno 或 pthread 直接错误码；无系统原因时为 0。 */
} vireo_log_error_t;

/** 进程内事件严重度；数值不作为 wire 或持久化 ABI。 */
typedef enum vireo_log_level {
    VIREO_LOG_LEVEL_DEBUG = 0, /**< 开发与细粒度诊断事件。 */
    VIREO_LOG_LEVEL_INFO = 1,  /**< 常规运行事件。 */
    VIREO_LOG_LEVEL_WARN = 2,  /**< 可继续运行但需要关注的异常。 */
    VIREO_LOG_LEVEL_ERROR = 3, /**< 操作或依赖已经失败的事件。 */
} vireo_log_level_t;

/** 调用期间只读的字节借用；不要求 NUL 终止或合法 UTF-8。 */
typedef struct vireo_log_span {
    uint8_t const *data; /**< 非零 size 时指向至少 size 个可读字节；空 span 可为 NULL。 */
    size_t size;        /**< 原始字节数；不靠 strlen 推导。 */
} vireo_log_span_t;

/** 单个日志事件；调用者负责排除密码、token、原始 chunk 等敏感内容。 */
typedef struct vireo_log_record {
    vireo_log_level_t level;       /**< 必须是四个已定义级别之一。 */
    vireo_log_span_t module;       /**< 模块名，最多 MAX_MODULE_SIZE 个字节；可为空。 */
    uint64_t connection_id;        /**< 连接关联身份；0 表示未提供，不是 fd。 */
    uint64_t generation;           /**< 连接复用代际；0 表示未提供。 */
    uint32_t sequence;             /**< 请求关联序号；0 表示未提供。 */
    vireo_log_span_t request_id;   /**< 请求关联字节，最多 MAX_ID_SIZE；空值输出空引号。 */
    vireo_log_span_t task_id;      /**< 任务关联字节，最多 MAX_ID_SIZE；空值输出空引号。 */
    vireo_log_span_t message;      /**< 事件消息，最多 MAX_MESSAGE_SIZE；允许任意字节。 */
} vireo_log_record_t;

/** 调用者已转换的 UTC 公历显示时间；formatter 不读取系统时钟。 */
typedef struct vireo_log_timestamp {
    uint16_t year;        /**< 1970～9999。 */
    uint8_t month;        /**< 1～12。 */
    uint8_t day;          /**< 1～当月天数，按公历闰年检查。 */
    uint8_t hour;         /**< 0～23。 */
    uint8_t minute;       /**< 0～59。 */
    uint8_t second;       /**< 0～59；本格式拒绝闰秒 60。 */
    uint32_t nanosecond;  /**< 0～999999999，显示为九位小数。 */
} vireo_log_timestamp_t;

/**
 * @brief 查询日志级别的固定 ASCII 名称
 * @param[in] level 任意级别值；未知值安全返回 "unknown"。
 * @return 静态只读非空字符串，已知值依次为 DEBUG、INFO、WARN、ERROR。
 * @note 所有权与生命周期：模块拥有，整个进程有效，不得修改或释放。
 * @note 线程安全：thread-safe，无共享可变状态。
 * @note errno：不读取、不保存、不修改 errno。
 */
char const *vireo_log_level_name(vireo_log_level_t level);

/**
 * @brief 把一个日志事件完整地格式化到调用者拥有的内存
 *
 * 格式固定为 UTC（YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ）、level、tid、module、
 * connection_id、generation、sequence、request_id、task_id、message，依此顺序。
 * 字段间是一个 ASCII 空格，后三种身份数字不补零；字符串用双引号包围。
 * printable ASCII 除 quote/backslash 外原样输出；quote/backslash 使用反斜杠转义，
 * LF/CR/HT 为 \n/\r/\t 文本，其他字节为严格两位大写 hex 的 \xHH 文本。
 * 空 span 显示为空引号；成功在完整行后追加唯一 LF 和一个 C NUL。
 *
 * @param[in] record 非空、调用期间不变的事件；四个 span 遵守各自上限。
 * @param[in] timestamp 非空、调用期间不变的有效 UTC 公历时间。
 * @param[in] thread_id 正的线程关联身份；本函数不验证它对应真实运行线程。
 * @param[out] buffer 非空，至少 capacity 个可写字节；调用者拥有。
 * @param[in] capacity 缓冲区总字节数，必须能容纳完整行和额外一个 NUL。
 * @param[out] out_size 非空；成功写入完整行长度，含 LF、不含 C NUL。
 * @retval VIREO_OK 完整行和长度已经提交。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必填指针为空、非空 span 缺指针、未知级别或零 thread_id。
 * @retval VIREO_RESULT_RANGE 时间、字段或行超出上限，或 capacity 不足。
 * @retval VIREO_RESULT_OVERFLOW 受检累计长度或终止符容量不可表示。
 * @note 输出保持：任何失败保持整个 buffer 和原 *out_size，不静默截断。
 * @note 所有权与生命周期：只借用输入/输出到返回，不保存指针，不分配内存。
 * @note 线程安全：thread-safe；共享输出或修改中的输入必须由调用者同步。
 * @note errno：不读取、不保存、不修改 errno；不执行 I/O 或系统调用。
 * @warning buffer、out_size 与 record、timestamp、所有 span 底层存储互不重叠，
 *          buffer 和 out_size 也不得重叠；输入必须在整个两遍处理期间保持不变。
 * @warning 转义不等于去敏；调用者不得传入凭据、完整 SQL 或敏感路径等内容。
 */
vireo_result_t vireo_log_format(vireo_log_record_t const *record,
                              vireo_log_timestamp_t const *timestamp,
                              uint64_t thread_id, char *buffer, size_t capacity,
                              size_t *out_size);

/**
 * @brief 获取所有请求的 sink 并成功才发布唯一拥有的 logger
 * @param[in] options 非空且稳定；至少启用 file 或 stderr 一个 sink。
 * @param[out] out_logger 非空且 *out_logger 必须为 NULL；成功转移所有权。
 * @param[out] out_error 可为 NULL；否则每次覆盖全部成员，成功为 NONE/NONE/0。
 * @retval VIREO_OK 所有请求资源已就绪，不代表已经写出日志或完成完整 logger。
 * @retval VIREO_RESULT_INVALID_ARGUMENT NULL、输出已占用、无 sink 或目录字符/绝对路径不合法。
 * @retval VIREO_RESULT_RANGE 目录在容量内未终止，或 file 阈值超出上下限。
 * @retval VIREO_RESULT_NO_MEMORY 对象分配失败，诊断为 ALLOCATE/ENOMEM。
 * @retval VIREO_RESULT_IO 目录/file/stderr 获取或检查失败，详见诊断。
 * @retval VIREO_RESULT_INTERNAL 对象 mutex 初始化失败，原因是 pthread 直接错误码。
 * @note 主要输出保持：失败不改 *out_logger；已获取 fd/heap 全部回收，不静默降级。
 * @note 所有权：仅调用期间借用选项/路径；复制路径和阈值，拥有内部所有 fd。
 * @note 文件：打开已有受信目录，不创建目录；固定 vireo.log 以 append/no-follow/CLOEXEC 打开，
 *       请求 mode 0640（受 umask 限制），不截断。要求普通单硬链接、当前有效 uid 拥有，
 *       禁止执行权限、group 写和 other 权限；不自动 chmod、unlink 或修复不合规文件。
 * @note 路径：裁剪末尾冗余 /；O_NOFOLLOW 不保护所有祖先，调用者负责目录及祖先可信。
 *       失败可以留下已创建的空文件；资源回滚不是目录项事务或完整路径沙箱。
 *       同一日志目录的 vireo.log/vireo.log.1 必须由唯一 logger 独占管理；禁止另一对象、
 *       进程、外部 logrotate 或其他写者同时操作这两个文件/目录项。不提供跨进程锁。
 * @note stderr：先复制并验证可写，再 open 其他资源，避免 fd 2 被复用；副本共享底层
 *       open file description。外部重定向不更新 logger，状态标志变更仍可能影响副本。
 * @note 线程安全：独立对象可并发；同一选项/输出及 stderr 重定向、umask 由调用者协调。
 * @note errno：保存并在所有路径恢复；不能通过返回后的 errno 读取本次错误。
 * @warning 输入和输出存储互不重叠；目录在容量内有效可读或正确 NUL 终止。
 * @warning 可能阻塞，非 signal-safe；不支持执行中的线程强制取消，不用于 Reactor 回调。
 */
vireo_result_t vireo_log_create(vireo_log_options_t const *options,
                              vireo_log_t **out_logger, vireo_log_error_t *out_error);

/**
 * @brief 在单对象锁内生成完整行，按 file-first、stderr-second 同步写入
 * @param[in,out] logger 非空、成功创建且未销毁的借用句柄；不转移所有权。
 * @param[in] record 非空；字段及 span 整次调用（包括等锁）稳定、可读，范围同 format。
 * @param[out] out_error 可为 NULL；否则覆盖全部成员，成功为 NONE/NONE/0。
 * @retval VIREO_OK 所有启用 sink 均完整接受该行，不表示稳定存储或整个模块封板。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必填指针为空、未知级别或非空 span 缺指针。
 * @retval VIREO_RESULT_RANGE 字段或采集到的 UTC 时间超范围。
 * @retval VIREO_RESULT_OVERFLOW 格式化受检长度无法表示。
 * @retval VIREO_RESULT_IO 时间采集/UTC 转换失败，或任一启用 sink 当前或以前已失败。
 * @retval VIREO_RESULT_INTERNAL mutex 失败或采集到无效线程身份。
 * @note 成功使用 CLOCK_REALTIME 显示 UTC 及 Linux 内核 TID；不保证事件因果总序。
 * @note 短写推进剩余字节；连续 EINTR 最多重试 16 次，正进度清零；零进度为 EIO。
 *       EAGAIN/EWOULDBLOCK 和其他 write 错误不等待，将该 sink 置 FAILED 并保存首错。
 * @note FAILED 保留 fd 所有权但不再 write；每次仍报告保存错误，继续尝试其他健康 sink。
 *       按 file/stderr 顺序选首错；无健康 sink 返回 IO。本阶段没有 reopen/retry API。
 * @note 输出保持：校验/采集/格式化失败不写 sink；I/O 失败可能已有半行或完整另一 sink，
 *       不回滚外部字节；不要盲目重试整条事件。NULL 诊断不影响处理或状态转换。
 * @note 所有权与生命周期：仅调用期间借用 record，不保存业务指针；内部 buffer 自有。
 * @note 轮转：健康 file 每次 fstat 核对大小/基本属性，下一行恰好达到阈值不轮转。
 *       超过时在同一目录 fd 下核对源项 dev/ino 与 file fd 相同，归档不存在或满足
 *       create 的普通单链接/uid/权限要求，然后 sync旧→rename→排他新建/检查→交接→close旧。
 *       成功轮转后写本行；只有当前和最近一份归档，再次轮转替换旧归档，早期历史会丢失。
 *       已有超阈值文件不截断，首次 emit 会整体归档；不保证其归档大小或外部增长总量。
 *       任一步失败将 file 置 FAILED，但仍尝试健康 stderr；rename后open失败仍拥有
 *       已改名旧 fd，新检查失败close新fd一次，交接后close旧失败仍持有新fd。
 *       可能留下归档、空新文件或没有当前名字；不回滚、不自动恢复或重试。
 *       close失败含EINTR不重试；不sync目录，不保证名字的断电恢复/文件系统事务。
 *       固定名称检查不抵御恶意并发目录修改，必须遵守 create 的独占与可信目录前提。
 * @note 线程安全：同一对象并发 emit/flush 为 thread-safe，整个处理由一个 mutex 串行化；
 *       调用者负责输入和共享诊断同步、停止/join 后 destroy；不同对象/进程无共同锁。
 * @note errno：保存并在所有路径恢复；具体原因从诊断读取，pthread 原因不是 errno。
 * @note SIGPIPE：每次实际 write 临时屏蔽调用线程 SIGPIPE，立即 EPIPE 或正短写后
 *       仅在原先无 pending 时消费可能新增的信号，再恢复原 mask；保留正进度，
 *       不改进程 disposition、不消费原有 pending，不用正返回后的 errno 判定错误。
 * @note 范围边界：无过滤、多级保留、自动恢复或 deadline；同步锁、轮转同步、
 *       磁盘/终端/阻塞管道均可能阻塞，非 Reactor-safe。正常 emit 不逐条 sync。
 * @warning 输入/诊断不得重叠；禁止并发 destroy、递归 emit、signal handler 调用、
 *          执行中的 pthread_cancel、fork 后未 exec 子进程使用继承对象。
 * @warning emit 期间不人工发送 SIGPIPE，否则无法区分来源；不管理其他进程信号。
 */
vireo_result_t vireo_log_emit(vireo_log_t *logger, vireo_log_record_t const *record,
                            vireo_log_error_t *out_error);

/**
 * @brief 在同一对象锁内显式同步健康 file 的数据，报告缓存 sink 首错
 * @param[in,out] logger 非空、已创建且未销毁的借用句柄；不转移所有权。
 * @param[out] out_error 可为 NULL；否则覆盖成员，成功为 NONE/NONE/0。
 * @retval VIREO_OK 健康 file 的 fdatasync 成功，或健康 stderr-only 的空操作成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT logger 为 NULL。
 * @retval VIREO_RESULT_IO file同步失败或任一启用sink已FAILED；固定file优先。
 * @retval VIREO_RESULT_INTERNAL mutex锁/解锁失败；诊断为pthread直接码。
 * @note 不写行、不取时钟/TID、不轮转；stderr无用户缓冲，不执行fflush/fdatasync。
 *       FAILED file不重新sync，报告保存首错；stderr已失败也不阻止健康file同步。
 *       首次sync失败转FAILED并保留fd至destroy；NULL诊断不改变行为。
 * @note 成功不保证目录项、其他设备、跨进程写入或断电后的名字/轮转恢复。
 * @note 线程安全：与同对象emit/flush串行，必须停止/join所有使用者后destroy。
 * @note errno：保存并在所有路径恢复；可能阻塞、非Reactor/signal-safe、无deadline。
 * @warning 诊断存储不与logger重叠；禁止递归、并发destroy、执行中pthread_cancel，
 *          或fork后未exec复用继承对象。I/O结果可能有部分成功，不盲目重试业务操作。
 */
vireo_result_t vireo_log_flush(vireo_log_t *logger, vireo_log_error_t *out_error);

/**
 * @brief 尽力同步、关闭和释放 logger，错误也消费对象并清空拥有者句柄
 * @param[in,out] inout_logger 非空；*inout_logger=NULL 为成功空操作，否则拥有唯一有效对象。
 * @param[out] out_error 可为 NULL；每次覆盖成员，按 sync/file/stderr/directory 顺序保留首错。
 * @retval VIREO_OK 清理成功或句柄已为空；不证明完整持久化/目录项崩溃恢复。
 * @retval VIREO_RESULT_INVALID_ARGUMENT inout_logger 为 NULL。
 * @retval VIREO_RESULT_IO file 同步或任一 close 失败；所有其余清理仍已尝试，对象已经消费。
 * @retval VIREO_RESULT_INTERNAL 先前 fd 清理无错但 mutex 销毁失败；对象仍已消费。
 * @note 所有权：无论 OK/IO 都 free 并置 *inout_logger=NULL，其他别名立即失效。
 * @note 清理：file 先 fdatasync；stderr 不 fflush/fdatasync；所有 fd 只 close 一次，
 *       然后销毁 mutex；该阶段无错才返回 OK，旧运行时失败不取代本次清理诊断。
 *       Linux close 失败（含 EINTR）不重试，避免关闭已被其他线程复用的描述符。
 * @note 线程安全：externally-synchronized；调用者必须先停止并等待所有使用者。
 * @note errno：保存并在全部路径恢复；不关闭调用者原始 stderr，不打印或递归记录错误。
 * @warning 句柄/诊断不得重叠或指向被消费对象；不得用旧别名重复释放或与使用并发。
 * @warning 可能阻塞，非 signal-safe，不支持执行中的 pthread_cancel。
 */
vireo_result_t vireo_log_destroy(vireo_log_t **inout_logger, vireo_log_error_t *out_error);

#endif /* VIREO_BASE_LOG_H */
