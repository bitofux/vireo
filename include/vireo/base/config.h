/*
 * PROJECT : VIREO
 * FILE    : config.h
 * AUTHOR  : bitofux
 * DATE    : 2026-09-25
 * BRIEF   : 此模块负责：
 * -- 定义启动配置、显式环境覆盖项和结构化错误诊断
 * -- 提供默认配置、配置文字解析和环境覆盖
 * -- 验证配置字段，并加载有界配置文件
 * -- 成功时提交完整配置，失败时保持主要输出
 */

#ifndef VIREO_BASE_CONFIG_H
#define VIREO_BASE_CONFIG_H

#include <vireo/base/result.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** 配置文字或配置文件允许的最大总字节数：64 KiB。 */
#define VIREO_CONFIG_MAX_TEXT_SIZE UINT32_C(65536)

/** 单行最大字节数；不包括结尾的 LF 或 CRLF。 */
#define VIREO_CONFIG_MAX_LINE_SIZE UINT32_C(2048)

/** 去掉两端空格和制表符之后，单个值的最大字节数。 */
#define VIREO_CONFIG_MAX_VALUE_SIZE UINT32_C(1023)

/** 路径数组容量，包含结尾的 NUL 字节。 */
#define VIREO_CONFIG_PATH_CAPACITY UINT32_C(1024)

/** 数字 IPv4 地址数组容量，包含结尾的 NUL 字节。 */
#define VIREO_CONFIG_ADDRESS_CAPACITY UINT32_C(16)

/** 一次调用最多接收的显式环境覆盖项数量。 */
#define VIREO_CONFIG_MAX_ENVIRONMENT_ITEMS UINT32_C(9)

/** 监听端口的最小允许值；v1 不使用端口 0。 */
#define VIREO_CONFIG_MIN_LISTEN_PORT UINT16_C(1)

/** 监听端口的最大允许值。 */
#define VIREO_CONFIG_MAX_LISTEN_PORT UINT16_C(65535)

/** 连接数量上限字段的最小允许值。 */
#define VIREO_CONFIG_MIN_MAX_CONNECTIONS UINT32_C(1)

/** 连接数量上限字段的最大允许值；属于 Vireo v1 配置限制。 */
#define VIREO_CONFIG_MAX_MAX_CONNECTIONS UINT32_C(65536)

/** 最小工作线程数量。 */
#define VIREO_CONFIG_MIN_WORKER_COUNT UINT32_C(1)

/** 最大工作线程数量；不表示系统一定能创建这么多线程。 */
#define VIREO_CONFIG_MAX_WORKER_COUNT UINT32_C(256)

/** 最小空闲超时，单位为毫秒。 */
#define VIREO_CONFIG_MIN_IDLE_TIMEOUT_MS UINT64_C(1)

/** 最大空闲超时：24 小时，单位为毫秒。 */
#define VIREO_CONFIG_MAX_IDLE_TIMEOUT_MS UINT64_C(86400000)

/** 最小日志文件大小阈值：1 MiB，单位为字节。 */
#define VIREO_CONFIG_MIN_LOG_FILE_SIZE_BYTES UINT64_C(1048576)

/** 最大日志文件大小阈值：1 GiB，单位为字节。 */
#define VIREO_CONFIG_MAX_LOG_FILE_SIZE_BYTES UINT64_C(1073741824)

/** 默认只监听 IPv4 回环地址。 */
#define VIREO_CONFIG_DEFAULT_LISTEN_ADDRESS "127.0.0.1"

/** 默认监听端口。 */
#define VIREO_CONFIG_DEFAULT_LISTEN_PORT UINT16_C(9000)

/** 默认连接数量上限。 */
#define VIREO_CONFIG_DEFAULT_MAX_CONNECTIONS UINT32_C(1024)

/** 默认工作线程数量。 */
#define VIREO_CONFIG_DEFAULT_WORKER_COUNT UINT32_C(4)

/** 默认空闲超时：60 秒，单位为毫秒。 */
#define VIREO_CONFIG_DEFAULT_IDLE_TIMEOUT_MS UINT64_C(60000)

/** 默认允许日志模块向标准错误输出日志。 */
#define VIREO_CONFIG_DEFAULT_LOG_TO_STDERR true

/** 默认日志文件大小阈值：64 MiB，单位为字节。 */
#define VIREO_CONFIG_DEFAULT_LOG_FILE_SIZE_BYTES UINT64_C(67108864)

/** 默认数据目录；本模块不负责创建或打开该目录。 */
#define VIREO_CONFIG_DEFAULT_DATA_DIR "/var/lib/vireo"

/** 默认日志目录；本模块不负责创建或打开该目录。 */
#define VIREO_CONFIG_DEFAULT_LOG_DIR "/var/log/vireo"

/**
 * @brief 标识一个已知配置字段
 *
 * 仅用于进程内诊断和字段识别，不是线协议编号，
 * 不允许直接序列化该枚举。
 */
typedef enum vireo_config_field {
    VIREO_CONFIG_FIELD_NONE = 0,
    /**< 没有对应字段，或者输入中的名称尚未被识别。 */

    VIREO_CONFIG_FIELD_LISTEN_ADDRESS,
    /**< 数字 IPv4 监听地址。 */

    VIREO_CONFIG_FIELD_LISTEN_PORT,
    /**< 监听端口。 */

    VIREO_CONFIG_FIELD_MAX_CONNECTIONS,
    /**< 连接数量上限。 */

    VIREO_CONFIG_FIELD_WORKER_COUNT,
    /**< 工作线程数量。 */

    VIREO_CONFIG_FIELD_IDLE_TIMEOUT,
    /**< 空闲超时；配置对象统一保存毫秒数。 */

    VIREO_CONFIG_FIELD_LOG_TO_STDERR,
    /**< 是否允许向标准错误输出日志。 */

    VIREO_CONFIG_FIELD_LOG_MAX_FILE_SIZE,
    /**< 日志文件大小阈值；配置对象统一保存字节数。 */

    VIREO_CONFIG_FIELD_DATA_DIR,
    /**< 数据目录。 */

    VIREO_CONFIG_FIELD_LOG_DIR,
    /**< 日志目录。 */
} vireo_config_field_t;

/**
 * @brief 配置错误所处的输入或处理阶段
 *
 * TEXT 表示配置文字的内容处理，
 * FILE 表示文件打开、读取或关闭操作；
 * 二者不能混为同一种错误。
 */
typedef enum vireo_config_source {
    VIREO_CONFIG_SOURCE_NONE = 0,
    /**< 无错误来源；也用于无法归属来源的调用参数错误。 */

    VIREO_CONFIG_SOURCE_CONFIG,
    /**< 基础配置或直接提供的配置对象不满足字段约束。 */

    VIREO_CONFIG_SOURCE_TEXT,
    /**< 配置文字的结构、字段或值有错误。 */

    VIREO_CONFIG_SOURCE_ENVIRONMENT,
    /**< 显式环境覆盖列表的名称、值或重复项有错误。 */

    VIREO_CONFIG_SOURCE_FILE,
    /**< 配置文件的打开、读取或关闭操作失败。 */
} vireo_config_source_t;

/**
 * @brief 配置处理的具体问题类别
 *
 * vireo_result_t 表达较宽的结果分类；
 * 本枚举进一步说明具体原因。
 * 本枚举不属于网络协议状态码。
 */
typedef enum vireo_config_issue {
    VIREO_CONFIG_ISSUE_NONE = 0,
    /**< 没有错误。 */

    VIREO_CONFIG_ISSUE_INVALID_ARGUMENT,
    /**< 禁止的空指针或其他可检查的调用参数错误。 */

    VIREO_CONFIG_ISSUE_TEXT_TOO_LARGE,
    /**< 完整配置文字或文件超过总长度上限。 */

    VIREO_CONFIG_ISSUE_LINE_TOO_LONG,
    /**< 某一行超过单行长度上限。 */

    VIREO_CONFIG_ISSUE_VALUE_TOO_LONG,
    /**< 值超过长度上限，或配置字符串未在字段容量内终止。 */

    VIREO_CONFIG_ISSUE_INVALID_CHARACTER,
    /**< 配置文字或字段包含不允许的字节。 */

    VIREO_CONFIG_ISSUE_MISSING_SEPARATOR,
    /**< 非空、非注释行缺少等号分隔符。 */

    VIREO_CONFIG_ISSUE_EMPTY_KEY,
    /**< 等号左侧去掉两端空白后没有配置键。 */

    VIREO_CONFIG_ISSUE_UNKNOWN_KEY,
    /**< 配置文件中的键不属于支持的精确名称集合。 */

    VIREO_CONFIG_ISSUE_DUPLICATE_KEY,
    /**< 同一次文字解析中，同一个已知键出现多次。 */

    VIREO_CONFIG_ISSUE_EMPTY_VALUE,
    /**< 已知字段的值在去掉两端空白后为空。 */

    VIREO_CONFIG_ISSUE_INVALID_INTEGER,
    /**< 普通整数不符合完整的无符号十进制语法。 */

    VIREO_CONFIG_ISSUE_INVALID_BOOLEAN,
    /**< 布尔值不是精确的小写 true 或 false。 */

    VIREO_CONFIG_ISSUE_INVALID_UNIT,
    /**< 大小或时长不符合规定的数字与单位语法。 */

    VIREO_CONFIG_ISSUE_INVALID_ADDRESS,
    /**< 地址不是本模块允许的数字 IPv4 形式。 */

    VIREO_CONFIG_ISSUE_INVALID_PATH,
    /**< 路径为空、不是绝对路径或包含不允许的内容。 */

    VIREO_CONFIG_ISSUE_VALUE_OUT_OF_RANGE,
    /**< 数值可以表示，但不满足该字段的允许范围。 */

    VIREO_CONFIG_ISSUE_NUMERIC_OVERFLOW,
    /**< 十进制累积或单位换算超过 uint64_t 的表示范围。 */

    VIREO_CONFIG_ISSUE_TOO_MANY_ENVIRONMENT_ITEMS,
    /**< 显式环境覆盖项数量超过接口上限。 */

    VIREO_CONFIG_ISSUE_UNKNOWN_ENVIRONMENT,
    /**< 显式提供的环境名称不属于支持的名称集合。 */

    VIREO_CONFIG_ISSUE_DUPLICATE_ENVIRONMENT,
    /**< 同一次覆盖中，同一个已知环境名称出现多次。 */

    VIREO_CONFIG_ISSUE_FILE_OPEN_FAILED,
    /**< 配置文件打开失败；具体系统原因保存在 system_errno。 */

    VIREO_CONFIG_ISSUE_FILE_READ_FAILED,
    /**< 配置文件读取失败；具体系统原因保存在 system_errno。 */

    VIREO_CONFIG_ISSUE_FILE_CLOSE_FAILED,
    /**< 配置文件关闭失败；具体系统原因保存在 system_errno。 */
} vireo_config_issue_t;

/**
 * @brief 成功解析后的拥有型启动配置
 *
 * 数值采用宿主语义，大小统一为字节，时长统一为毫秒。
 * 字符串保存在对象自身的数组中，不借用原始输入。
 *
 * @note 所有权：对象及其全部成员由调用者持有。
 * @note 生命周期：不包含需要单独释放的动态字符串。
 * @note 线程安全：构造和修改需要独占访问；
 *       安全发布之后可由多个线程只读访问，
 *       所有读取结束前不得修改或销毁对象。
 * @note 不可变快照是使用合同，不表示所有成员在 C 类型上为 const。
 * @note 配置验证成功不保证 socket、线程、目录或文件能创建成功。
 * @note 不冻结结构体的 sizeof、填充字节或 ABI，不可直接序列化。
 */
typedef struct vireo_config {
    char listen_address[VIREO_CONFIG_ADDRESS_CAPACITY];
    /**< NUL 终止的数字 IPv4 地址；四段十进制，每段 0..255。
         除单独的 0 外，每段不得有前导零；不接受主机名或 IPv6。 */

    uint16_t listen_port;
    /**< 监听端口，范围为 1..65535。 */

    uint32_t max_connections;
    /**< 连接数量上限，范围为 1..65536；不在本模块分配连接。 */

    uint32_t worker_count;
    /**< 工作线程数量，范围为 1..256；不在本模块创建线程。 */

    uint64_t idle_timeout_ms;
    /**< 空闲超时，单位毫秒，范围为 1..86400000。 */

    bool log_to_stderr;
    /**< 是否允许后续日志模块向标准错误输出日志。 */

    uint64_t log_max_file_size_bytes;
    /**< 日志文件大小阈值，单位字节，范围为 1 MiB..1 GiB。
         实际轮转时机由日志模块负责，本字段不保证文件绝不越过阈值。 */

    char data_dir[VIREO_CONFIG_PATH_CAPACITY];
    /**< NUL 终止的非空绝对路径，内容最多 1023 字节。
         拒绝 ASCII 控制字节和 DEL，不检查目录存在性或权限。 */

    char log_dir[VIREO_CONFIG_PATH_CAPACITY];
    /**< NUL 终止的非空绝对路径，内容最多 1023 字节。
         拒绝 ASCII 控制字节和 DEL，不执行路径规范化或符号链接解析。 */
} vireo_config_t;

/**
 * @brief 一项由调用者显式提供的环境覆盖
 *
 * 不存在的环境变量不应放入列表。
 * 存在但为空的环境变量必须提供非空指针指向空字符串，
 * 不得用 NULL 表示空字符串。
 *
 * @note name 和 value 必须指向生命周期内、正确 NUL 终止的字符串。
 * @note 所有权：两个字符串均由调用者保留所有权。
 * @note 生命周期：只在当前调用期间借用，不保存输入指针。
 * @note 线程安全：调用期间不得修改项或其字符串内容。
 */
typedef struct vireo_config_environment {
    char const *name;
    /**< 非空名称指针；名称必须精确匹配支持的 VIREO_ 环境名称。 */

    char const *value;
    /**< 非空值指针；允许指向空字符串，但当前九个字段均拒绝空值。 */
} vireo_config_environment_t;

/**
 * @brief 配置处理的结构化错误信息
 *
 * 不保存原始配置值、整行内容或输入字符串指针。
 * 无错误状态为 NONE 来源、NONE 字段、NONE issue，
 * 其余成员全部为 0。
 *
 * @note 所有权：对象由调用者创建并持有，无动态资源。
 * @note 输出规则：诊断输出允许在失败时更新，
 *       与主要配置输出的失败保持规则不同。
 * @note 多种错误同时存在时，不承诺所有错误之间的完整优先级。
 */
typedef struct vireo_config_error {
    vireo_config_issue_t issue;
    /**< 本次失败的具体原因；成功时为 NONE。 */

    vireo_config_source_t source;
    /**< 错误所属来源或处理阶段。 */

    vireo_config_field_t field;
    /**< 已识别的相关字段；未知键或无法确定字段时为 NONE。 */

    size_t line;
    /**< 配置文字行号，从 1 开始；不适用或无法定位时为 0。 */

    size_t entry_index;
    /**< 环境列表位置，从 1 开始；不适用或无法定位时为 0。 */

    int system_errno;
    /**< 文件操作失败时保存的可用底层 errno；
         非文件操作错误或无可用系统错误值时为 0。 */
} vireo_config_error_t;

/*
 * 配置文字和环境值的统一规则：
 *
 * 1. 文件键区分大小写，仅接受以下精确名称：
 *    listen_address、listen_port、max_connections、worker_count、
 *    idle_timeout、log_to_stderr、log_max_file_size、data_dir、log_dir。
 *
 * 2. 环境名称按相同顺序对应：
 *    VIREO_LISTEN_ADDRESS、VIREO_LISTEN_PORT、VIREO_MAX_CONNECTIONS、
 *    VIREO_WORKER_COUNT、VIREO_IDLE_TIMEOUT、VIREO_LOG_TO_STDERR、
 *    VIREO_LOG_MAX_FILE_SIZE、VIREO_DATA_DIR、VIREO_LOG_DIR。
 *
 * 3. 普通整数只接受一个或多个 ASCII 十进制数字。
 *    允许前导零，始终按十进制解释；拒绝正负号、小数和其他尾随内容。
 *
 * 4. 布尔值只接受精确的小写 true 或 false。
 *
 * 5. 大小接受十进制数字，后接可选的 B、KiB、MiB 或 GiB；
 *    无后缀表示字节。时长接受十进制数字，后接可选的 ms、s 或 m；
 *    无后缀表示毫秒。数字与后缀之间不得插入空白。
 *
 * 6. 值的两端只去掉 ASCII 空格和水平制表符。
 *    不展开变量，不执行转义，也不把引号当作字符串定界符；
 *    引号若出现，只是普通值字节，仍受对应字段规则约束。
 *
 * 7. 路径要求首字节为 '/'，不允许内容中的 ASCII 控制字节或 DEL；
 *    不验证 UTF-8，不执行 Unicode 或文件系统路径规范化，
 *    不证明路径存在、可访问或位于某个安全根目录。
 *
 * 8. 全部接口只检查能够从合法 C 对象中检查的约束，
 *    不验证任意非空指针是否真实有效。
 *    被读取的对象成员必须具有确定值。
 *    可写输出之间、可写输出与任何输入对象或输入存储不得重叠。
 */

/**
 * @brief 生成一份完整的默认配置
 *
 * 为全部配置成员设置默认值，字符串复制到对象自身的数组。
 * 不读取文件或进程环境。
 *
 * @param[out] out_config
 *     非空、可写配置对象指针；调用者保留对象所有权。
 *
 * @retval VIREO_OK
 *     已写入满足 v1 字段约束的完整默认配置。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     out_config 为 NULL。
 *
 * @note 输出保持：唯一失败情况没有可写输出对象；
 *       成功时覆盖全部配置成员，不承诺结构体填充字节的值。
 * @note 所有权：不接管 out_config，不需要配套释放函数。
 * @note 生命周期：不保存参数指针，字符串由输出对象自身持有。
 * @note 线程安全：不使用共享可变状态；
 *       对同一输出对象的访问需要调用者同步。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不创建目录、日志、线程或网络资源，
 *       不保证默认资源在当前机器上能够成功初始化。
 */
vireo_result_t vireo_config_defaults(vireo_config_t *out_config);

/**
 * @brief 验证一份配置对象是否满足 v1 字段约束
 *
 * 检查数值范围、数字 IPv4 地址和有界路径字符串。
 * 字符串必须在各自数组容量内出现 NUL 终止符。
 *
 * @param[in] config
 *     非空、只读配置对象；全部成员必须具有确定值，
 *     包括有效的 bool 对象表示。
 *
 * @param[out] out_error
 *     非空、可写诊断对象；
 *     调用开始时重置为无错误状态。
 *
 * @retval VIREO_OK
 *     配置满足全部当前字段约束，out_error 为无错误状态。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需指针为空，或者地址、路径内容不符合字段规则。
 *
 * @retval VIREO_RESULT_RANGE
 *     数值超出字段范围，或者字符串未在字段容量内终止。
 *
 * @note 输出保持：始终不修改 config；
 *       out_error 非 NULL 时允许重置或写入诊断。
 * @note 所有权：不接管任何对象，不动态分配内存。
 * @note 生命周期：只在调用期间借用 config，不保存指针。
 * @note 线程安全：不使用共享可变状态；
 *       调用期间 config 不得被并发修改，诊断输出需要独占访问。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不检查端口占用、系统资源、文件存在性或权限，
 *       不打印错误，也不调用日志模块。
 */
vireo_result_t vireo_config_validate(vireo_config_t const *config, vireo_config_error_t *out_error);

/**
 * @brief 在基础配置上应用一段配置文字，成功时提交完整结果
 *
 * 先验证基础配置，再解析输入。
 * 每行使用第一个 '=' 分隔键和值；去掉键和值两端的空格和制表符。
 * 支持空输入、空行、整行 '#' 注释、LF、CRLF 和无末尾换行。
 * '#' 只有在去掉行首空白后位于首字节时才引入注释；
 * 不支持行尾注释、分组、包含文件或变量展开。
 *
 * 输入中的 NUL、DEL 和除 HT、LF、合法 CRLF 之外的 ASCII 控制字节
 * 均被拒绝；裸 CR 不作为换行接受。
 * 已知键不得在同一次解析中重复，即使值相同也拒绝。
 * 解析成功后验证完整候选配置，再提交 out_config。
 *
 * @param[in] base
 *     非空、只读基础配置；
 *     未在文字中出现的字段保留基础配置的值。
 *
 * @param[in] text
 *     只读输入字节区域，不要求 NUL 终止；
 *     text_size 为 0 时允许为 NULL，
 *     否则必须指向至少 text_size 个可读字节。
 *
 * @param[in] text_size
 *     输入总字节数，包含换行字节；
 *     不得超过 VIREO_CONFIG_MAX_TEXT_SIZE。
 *
 * @param[out] out_config
 *     非空、可写配置输出；不得与 base 或输入区域重叠。
 *
 * @param[out] out_error
 *     非空、可写诊断输出；不得与其他输入输出重叠。
 *     文字错误尽可能提供从 1 开始的行号。
 *
 * @retval VIREO_OK
 *     全部输入已处理，完整配置已提交，诊断为无错误状态。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     调用参数、基础配置、文字语法、键或值的形式不合法。
 *
 * @retval VIREO_RESULT_RANGE
 *     基础配置范围不合法，输入、行或值超长，
 *     或解析后的数值超出字段允许范围。
 *
 * @retval VIREO_RESULT_OVERFLOW
 *     十进制累积或单位换算超过 uint64_t 的表示范围。
 *
 * @note 输出保持：所有失败均保持 out_config 的原有成员值；
 *       out_error 非 NULL 时允许重置并更新。
 * @note 所有权：不接管输入或输出，不保存输入中的字符串指针。
 * @note 生命周期：输入仅在调用期间借用；
 *       成功结果中的字符串由 out_config 自身持有。
 * @note 线程安全：不使用共享可变状态；
 *       输入在调用期间不得变化，输出对象需要独占访问。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不执行文件 I/O，不读取进程环境，
 *       不进行热更新或初始化任何运行时资源。
 */
vireo_result_t vireo_config_parse_text(vireo_config_t const *base, char const *text,
                                       size_t text_size, vireo_config_t *out_config,
                                       vireo_config_error_t *out_error);

/**
 * @brief 在基础配置上应用显式环境覆盖项
 *
 * 先验证基础配置，再按数组顺序检查和应用覆盖。
 * 环境名称必须精确匹配支持列表；未知或重复名称均被拒绝。
 * 值使用与配置文字相同的字段转换和范围检查规则。
 * 环境值不是配置文件行，不解释注释或等号分隔符。
 *
 * @param[in] base
 *     非空、只读基础配置；未被覆盖的字段保持基础值。
 *
 * @param[in] environment
 *     只读覆盖项数组；
 *     environment_count 为 0 时允许为 NULL，
 *     否则必须指向至少 environment_count 个有效项。
 *     每项的 name 和 value 都必须是非空的有效 C 字符串指针。
 *
 * @param[in] environment_count
 *     数组元素数量，不是字节数；
 *     不得超过 VIREO_CONFIG_MAX_ENVIRONMENT_ITEMS。
 *
 * @param[out] out_config
 *     非空、可写配置输出，不得与基础配置或任何输入存储重叠。
 *
 * @param[out] out_error
 *     非空、可写诊断输出；
 *     项级错误尽可能提供从 1 开始的 entry_index。
 *
 * @retval VIREO_OK
 *     全部覆盖已应用并通过验证，完整结果已提交。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     参数或基础配置不合法，环境名称未知或重复，
 *     或环境值不符合字段语法。
 *
 * @retval VIREO_RESULT_RANGE
 *     项数量超限、值过长，或配置数值超出字段范围。
 *
 * @retval VIREO_RESULT_OVERFLOW
 *     数字累积或单位换算超过 uint64_t 的表示范围。
 *
 * @note 输出保持：任何失败均保持 out_config 的原有成员值；
 *       out_error 非 NULL 时允许重置并更新。
 * @note 所有权：不接管数组、字符串或输出对象，不动态分配内存。
 * @note 生命周期：只在调用期间借用环境项；
 *       成功后不保存 name 或 value 指针。
 * @note 线程安全：不读取或修改进程环境，不使用共享可变状态；
 *       调用期间输入不得变化，输出对象需要独占访问。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不调用 getenv、setenv 或 unsetenv，
 *       不打开配置文件，不打印诊断，不初始化运行时资源。
 */
vireo_result_t vireo_config_apply_environment(vireo_config_t const *base,
                                              vireo_config_environment_t const *environment,
                                              size_t environment_count, vireo_config_t *out_config,
                                              vireo_config_error_t *out_error);

/**
 * @brief 按默认值、可选文件和显式环境覆盖的顺序加载完整配置
 *
 * 顺序固定为：
 * 默认配置 -> 可选配置文件 -> 显式环境覆盖 -> 最终验证 -> 提交输出。
 *
 * 明确指定的文件必须成功打开、读取并关闭。
 * 文件内容错误不会因为后续环境覆盖可能替换该字段而被忽略。
 * 文件读取受 VIREO_CONFIG_MAX_TEXT_SIZE 限制，
 * 必须区分恰好达到上限与仍存在额外输入。
 *
 * @param[in] file_path
 *     配置文件路径；
 *     NULL 表示主动跳过文件来源；
 *     非 NULL 时必须指向非空、有效、NUL 终止的路径字符串。
 *     配置文件路径允许相对路径，按调用时的进程工作目录解释；
 *     它与配置中的 data_dir、log_dir 绝对路径约束不同。
 *
 * @param[in] environment
 *     调用者显式提供的环境覆盖项数组；
 *     environment_count 为 0 时允许为 NULL。
 *     项的名称、值和生命周期要求与 apply_environment 相同。
 *
 * @param[in] environment_count
 *     环境覆盖项数量；
 *     不得超过 VIREO_CONFIG_MAX_ENVIRONMENT_ITEMS。
 *
 * @param[out] out_config
 *     非空、可写配置输出；
 *     与 file_path、环境数组、环境字符串和 out_error 均不得重叠。
 *
 * @param[out] out_error
 *     非空、可写诊断输出；
 *     文件内容错误使用 TEXT 来源，
 *     文件操作错误使用 FILE 来源并保存可用的 system_errno。
 *
 * @retval VIREO_OK
 *     所有选定来源处理成功，文件资源已关闭，
 *     完整配置已提交，诊断为无错误状态。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     参数、配置文字、环境覆盖或字段内容不合法。
 *
 * @retval VIREO_RESULT_RANGE
 *     文件、文字、行、值或覆盖项数量超限，
 *     或最终数值超出字段范围。
 *
 * @retval VIREO_RESULT_OVERFLOW
 *     数字累积或单位换算超过 uint64_t 的表示范围。
 *
 * @retval VIREO_RESULT_NOT_FOUND
 *     指定文件打开失败，底层原因是 ENOENT。
 *
 * @retval VIREO_RESULT_IO
 *     其他文件打开、读取或关闭错误。
 *
 * @note 输出保持：任何失败均保持 out_config 的原有成员值，
 *       不提交只有部分来源生效的候选配置；
 *       out_error 非 NULL 时允许重置并更新。
 * @note 所有权：不接管调用者的路径、环境项或输出对象；
 *       本函数负责清理自己获取的文件资源。
 * @note 生命周期：不保存任何输入指针；
 *       成功配置中的字符串由 out_config 自身持有。
 * @note 线程安全：不使用共享可变项目状态，不读取进程环境；
 *       输入在调用期间不得变化，输出需要独占访问。
 *       本函数可能阻塞，应在启动阶段调用，不在 Reactor 回调中调用。
 * @note errno：返回前恢复调用前的 errno；
 *       文件操作失败的可用底层原因保存在 out_error->system_errno。
 * @note 错误清理：发生错误后仍清理已获取资源；
 *       后续清理错误不覆盖已经记录的主要错误。
 *       若此前没有错误但关闭失败，则报告关闭错误且不提交配置。
 * @note 范围边界：不创建目录、日志、线程、socket 或数据库连接，
 *       不执行热更新；不保证并发修改中的配置文件具有原子快照语义。
 *       调用者应提供可信、稳定且适合启动阶段读取的文件来源。
 */
vireo_result_t vireo_config_load(char const *file_path,
                                 vireo_config_environment_t const *environment,
                                 size_t environment_count, vireo_config_t *out_config,
                                 vireo_config_error_t *out_error);

#endif  // VIREO_BASE_CONFIG_H
