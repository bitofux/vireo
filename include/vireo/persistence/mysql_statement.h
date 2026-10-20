#ifndef VIREO_PERSISTENCE_MYSQL_STATEMENT_H
#define VIREO_PERSISTENCE_MYSQL_STATEMENT_H
#include <stdbool.h>
#include <stddef.h>
#include <vireo/persistence/mysql.h>

/** @brief SQL模板最大字节数，不含终止符。 */
#define VIREO_MYSQL_SQL_MAX 65536
/** @brief 参数marker数量硬上限，允许零参数。 */
#define VIREO_MYSQL_PARAMETERS_MAX 32
/** @brief 输出列数硬上限，允许无列语句。 */
#define VIREO_MYSQL_COLUMNS_MAX 32
/** @brief TEXT/BYTES参数总字节硬上限。 */
#define VIREO_MYSQL_PARAMETER_BYTES_MAX 1048576
/** @brief 每列有效字节硬上限，不含内部余量。 */
#define VIREO_MYSQL_CELL_BYTES_MAX 65536
/** @brief wrapper自有申请总量硬上限，不包含驱动/服务器/RSS。 */
#define VIREO_MYSQL_STATEMENT_MEMORY_MAX 4194304

/** @brief 唯一语句owner；保活父连接，整个连接资源图须外部排他。 */
typedef struct vireo_mysql_statement vireo_mysql_statement_t;
/** @brief 显式容量，prepare一次申请，execute/fetch不扩wrapper内存。 */
typedef struct vireo_mysql_statement_limits {
    size_t max_parameters; /**< 0..32。 */
    size_t max_columns; /**< 0..32，execute后再次核实际列数。 */
    size_t max_parameter_bytes; /**< 0..1048576，整数不占该字节区。 */
    size_t max_cell_bytes; /**< 1..65536，每列有效字节。 */
    size_t max_memory_bytes; /**< 1..4194304，含wrapper及所有工作区。 */
} vireo_mysql_statement_limits_t;
/** @brief 活跃union成员由kind唯一确定，NULL不读取union。 */
typedef enum vireo_mysql_parameter_kind {
    VIREO_MYSQL_PARAMETER_NULL, /**< SQL NULL。 */
    VIREO_MYSQL_PARAMETER_I64, /**< 有符号原生LONGLONG。 */
    VIREO_MYSQL_PARAMETER_U64, /**< 无符号原生LONGLONG。 */
    VIREO_MYSQL_PARAMETER_TEXT, /**< utf8mb4字节，数据库核字符有效性。 */
    VIREO_MYSQL_PARAMETER_BYTES /**< 不解释编码，允许二进制NUL。 */
} vireo_mysql_parameter_kind_t;
/** @brief execute短借，先复制到自有区再交同步驱动消费；不保留caller地址。 */
typedef struct vireo_mysql_parameter {
    vireo_mysql_parameter_kind_t kind; /**< 决定唯一活跃成员。 */
    union {
        int64_t i64; /**< I64值。 */
        uint64_t u64; /**< U64值。 */
        struct {
            const void *data; /**< TEXT/BYTES可读字节，length为零允许NULL。 */
            size_t length; /**< 有效字节数，计入总参数字节预算。 */
        } span; /**< TEXT/BYTES活跃成员。 */
    } value; /**< NULL不读取，其他只读对应成员。 */
} vireo_mysql_parameter_t;
/** @brief 本层状态，不代表数据库事务状态。 */
typedef enum vireo_mysql_statement_state {
    VIREO_MYSQL_STATEMENT_READY, /**< 可execute。 */
    VIREO_MYSQL_STATEMENT_ROWS, /**< 结果待fetch，占用父连接。 */
    VIREO_MYSQL_STATEMENT_ROW, /**< 完整当前行已发布。 */
    VIREO_MYSQL_STATEMENT_DONE, /**< 当前执行完成，重新execute前须reset。 */
    VIREO_MYSQL_STATEMENT_FAILED /**< 须reset或destroy；损坏父连接只能destroy。 */
} vireo_mysql_statement_state_t;
/** @brief 无I/O值快照。 */
typedef struct vireo_mysql_statement_info {
    vireo_mysql_statement_state_t state; /**< 本层状态。 */
    size_t parameter_count; /**< prepare得到的实际marker数。 */
    size_t column_count; /**< 最近成功取得的prepare/execute元数据列数。 */
    size_t allocated_bytes; /**< 本层实际申请量，不含原生分配。 */
} vireo_mysql_statement_info_t;
/** @brief 每次execute先清零，即使失败也写入；不可用started推断提交成功。 */
typedef struct vireo_mysql_execution {
    bool execution_started; /**< 原生execute调用前才置true；false证明未调用。 */
    bool has_result; /**< 仅OK有意义，包括零行SELECT。 */
    uint64_t affected_rows; /**< 仅OK且无结果时有效；UPDATE为changed rows。 */
    uint64_t insert_id; /**< 仅OK且无结果时有效；零不是失败。 */
} vireo_mysql_execution_t;
/** @brief fetch完整行或结果结束。 */
typedef enum vireo_mysql_fetch_outcome {
    VIREO_MYSQL_FETCH_ROW, /**< 所有列完整，可column。 */
    VIREO_MYSQL_FETCH_DONE /**< 无更多行；健康DONE可重复无I/O。 */
} vireo_mysql_fetch_outcome_t;
/** @brief 当前行短借视图；下次合法fetch/reset/destroy使其失效。 */
typedef struct vireo_mysql_cell_view {
    const unsigned char *data; /**< SQL NULL为NULL；非NULL空值仍有零长视图。 */
    size_t length; /**< 有效字节，不承诺C终止符。 */
    bool is_null; /**< true时data=NULL且length=0。 */
} vireo_mysql_cell_view_t;

/**
 * @brief 对可信SQL模板创建原生预处理语句，不拼接外部SQL，不公开原生handle。
 * @param[in] thread 当前OS线程同runtime guard，不得跨线程转移guard。
 * @param[in] connection 存活父连接；live子语句阻止connection_destroy。
 * @param[in] sql 非NULL、无嵌入NUL的可信模板，仅短借，不要求额外终止符。
 * @param[in] sql_length 1..65536字节；参数只能替代值，不能替代标识符。
 * @param[in] limits 五项显式容量；零cell/memory无效。
 * @param[out] out_statement 必需NULL owner地址，失败保持。
 * @param[out] error 可选，每次重置，无SQL/参数/原始文本。
 * @retval VIREO_OK 完整READY owner发布。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 地址/guard/SQL/零必需容量无效。
 * @retval VIREO_RESULT_RANGE 硬上限、实际marker/列或内存预算超限。
 * @retval VIREO_RESULT_OVERFLOW 布局、窄化或父计数不可表示。
 * @retval VIREO_RESULT_NO_MEMORY wrapper或原生init申请失败。
 * @retval VIREO_RESULT_BUSY 父连接被未读/失败语句占用。
 * @retval VIREO_RESULT_CANCELLED 父连接已损坏。
 * @retval VIREO_RESULT_DATABASE 原生prepare/metadata失败。
 * @note 七入口均保持errno。所有地址须存活、对齐、互不覆盖且不指向errno；
 *       整个连接和所有子语句外部串行；独立连接完整图可在操作/借用结束后同步交接。
 *       池内连接和子语句仅能由租借OS线程在有效租期内使用，须先销毁子语句再归还。
 *       可能阻塞，驱动阶段等待不是硬总期限。无事务/重试/重连/多结果支持。
 */
vireo_result_t vireo_mysql_statement_prepare(vireo_mysql_thread_t *thread,
    vireo_mysql_connection_t *connection, const char *sql, size_t sql_length,
    const vireo_mysql_statement_limits_t *limits,
    vireo_mysql_statement_t **out_statement, vireo_mysql_error_t *error);
/**
 * @brief 无I/O复制语句快照，损坏连接也允许，不是健康检查。
 * @param[in] thread 当前线程同runtime guard。
 * @param[in] statement 存活语句，外部排他。
 * @param[out] out_info 必需，只有OK写入。
 * @retval VIREO_OK 已复制快照。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需地址/guard无效。
 * @note 保持errno，无分配，其他通用地址/同步前置同prepare。
 */
vireo_result_t vireo_mysql_statement_inspect(vireo_mysql_thread_t *thread,
    const vireo_mysql_statement_t *statement, vireo_mysql_statement_info_t *out_info);
/**
 * @brief 完整校验并复制参数到自有区，再绑定并最多调用一次原生execute。
 * @param[in] thread 当前线程同runtime guard。
 * @param[in,out] statement 必须READY且父连接未被其他语句占用。
 * @param[in] parameters active union数组，数量零允许NULL；span非零须有data。
 * @param[in] parameter_count 必须等于实际marker数。
 * @param[out] out_execution 必需，每次先清零；失败也可写started。
 * @param[out] error 可选，每次重置。
 * @retval VIREO_OK 有列进入ROWS，无列进入DONE。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 地址/guard/count/tag/span无效。
 * @retval VIREO_RESULT_RANGE 参数字节预算或执行后实际列数超限。
 * @retval VIREO_RESULT_OVERFLOW 原生长度无法表示。
 * @retval VIREO_RESULT_BUSY 非READY或其他语句占用。
 * @retval VIREO_RESULT_CANCELLED FAILED或父连接损坏。
 * @retval VIREO_RESULT_DATABASE 绑定/执行/元数据/额外结果失败。
 * @note 保持errno；started=true不证明成功/提交，禁止据错误自动重放写操作。
 *       参数绑定始终引用自有存储；同步原生execute返回即擦本层参数值，绑定失败亦擦。
 *       caller输入保持，绑定地址继续存活；不承诺驱动/服务端副本擦除。
 */
vireo_result_t vireo_mysql_statement_execute(vireo_mysql_thread_t *thread,
    vireo_mysql_statement_t *statement, const vireo_mysql_parameter_t *parameters,
    size_t parameter_count, vireo_mysql_execution_t *out_execution, vireo_mysql_error_t *error);
/**
 * @brief 非缓冲读取至多一行，所有列以MYSQL_TYPE_STRING字节返回，截断整行拒绝。
 * @param[in] thread 当前线程同runtime guard。
 * @param[in,out] statement ROWS/ROW，健康DONE幂等。
 * @param[out] out_outcome 必需，仅OK写入ROW或DONE。
 * @param[out] error 可选，每次重置。
 * @retval VIREO_OK 完整当前行或EOF。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 地址/guard无效，不推进借用。
 * @retval VIREO_RESULT_BUSY READY。
 * @retval VIREO_RESULT_CANCELLED FAILED或父连接损坏。
 * @retval VIREO_RESULT_RANGE 任意列超限或原生截断，FAILED且整行不发布。
 * @retval VIREO_RESULT_DATABASE 原生fetch/清理/额外结果失败。
 * @note 保持errno；合法fetch包括EOF/失败均使旧view失效。无全结果缓存，
 *       调用驱动前擦旧行区；完整新行才保留，EOF/失败擦可能写入的片段。
 *       wrapper预算不限制驱动packet/RSS/服务端；numeric为驱动字符串，binary保留NUL。
 */
vireo_result_t vireo_mysql_statement_fetch(vireo_mysql_thread_t *thread,
    vireo_mysql_statement_t *statement, vireo_mysql_fetch_outcome_t *out_outcome,
    vireo_mysql_error_t *error);
/**
 * @brief 借当前完整行一列，无I/O，不解析数值/DTO或假设全部列UTF-8。
 * @param[in] thread 当前线程同runtime guard。
 * @param[in] statement 必须ROW，整个连接排他。
 * @param[in] column_index 零基索引，小于实际列数。
 * @param[out] out_cell 必需，仅OK写入，须在下次合法fetch/reset/destroy前复制所需数据。
 * @retval VIREO_OK 获得短借视图。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 地址/guard无效。
 * @retval VIREO_RESULT_RANGE 索引超界。
 * @retval VIREO_RESULT_BUSY 非ROW。
 * @retval VIREO_RESULT_CANCELLED FAILED或父连接损坏。
 * @note 保持errno；SQL NULL与非NULL空值由is_null区分。
 */
vireo_result_t vireo_mysql_statement_column(vireo_mysql_thread_t *thread,
    const vireo_mysql_statement_t *statement, size_t column_index, vireo_mysql_cell_view_t *out_cell);
/**
 * @brief 释放未读结果、原生reset并清本层参数/行，成功READY；不是事务ROLLBACK。
 * @param[in] thread 当前线程同runtime guard。
 * @param[in,out] statement 存活语句；原生bindings不清，故自有存储保留至destroy。
 * @param[out] error 可选，每次重置。
 * @retval VIREO_OK 可重新绑定执行。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 地址/guard无效。
 * @retval VIREO_RESULT_BUSY 另一语句占用父连接。
 * @retval VIREO_RESULT_CANCELLED 父连接损坏。
 * @retval VIREO_RESULT_DATABASE free/reset/额外结果失败，父连接标记损坏。
 * @note 保持errno；通过地址/损坏/占用门禁即撤销当前行并擦本层参数/行区，
 *       后续原生清理失败也不恢复旧值；门禁拒绝保持本层值。
 *       无本层新申请，失败不恢复事务或已发生副作用。
 */
vireo_result_t vireo_mysql_statement_reset(vireo_mysql_thread_t *thread,
    vireo_mysql_statement_t *statement, vireo_mysql_error_t *error);
/**
 * @brief 关闭原生语句并解除父保活；一旦进入close即消耗owner，包括close报错。
 * @param[in] thread 非空owner必需当前同runtime guard；空owner允许NULL。
 * @param[in,out] statement 必需owner地址；空owner幂等OK。
 * @param[out] error 可选，每次重置，close失败从仍live父连接取诊断。
 * @retval VIREO_OK 已释放或原本为空。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 地址/guard无效，owner保持。
 * @retval VIREO_RESULT_BUSY 另一语句占用健康父连接，owner保持。
 * @retval VIREO_RESULT_DATABASE close失败或额外结果，owner已清、父连接损坏。
 * @note 保持errno；损坏连接允许逐个destroy，不能重试已消耗的owner；可能阻塞。
 */
vireo_result_t vireo_mysql_statement_destroy(vireo_mysql_thread_t *thread,
    vireo_mysql_statement_t **statement, vireo_mysql_error_t *error);
#endif
