/* PROJECT : VIREO
 * BRIEF   : 有界 Argon2id 密码设施；同步计算，不持有网络或账户资源。
 */
#ifndef VIREO_SECURITY_PASSWORD_H
#define VIREO_SECURITY_PASSWORD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <vireo/base/result.h>

/** @brief PHC 输出的最小容量，包含结尾 NUL；输入长度不包含 NUL。 */
#define VIREO_PASSWORD_ENCODED_CAPACITY 128

/** @brief 单次运算策略；调用期间只读，不是全进程并发配额。 */
typedef struct vireo_password_policy {
    uint32_t create_memory_kib; /**< 生成矩阵参数，65536～262144 KiB。 */
    uint32_t create_iterations; /**< 生成轮数，3～10。 */
    uint32_t max_verify_memory_kib; /**< 校验上限，覆盖生成值且至多262144。 */
    uint32_t max_verify_iterations; /**< 校验上限，覆盖生成值且至多10。 */
    size_t max_password_bytes; /**< 密码长度上限，1～4096字节。 */
} vireo_password_policy_t;

/** @brief 默认64MiB/3轮，校验至多256MiB/10轮，密码至多1024字节。 */
#define VIREO_PASSWORD_POLICY_DEFAULT \
    {UINT32_C(65536), UINT32_C(3), UINT32_C(262144), UINT32_C(10), (size_t)1024}

/** @brief 经过格式与成本检查的记录信息，不表示密码已经校验成功。 */
typedef struct vireo_password_info {
    uint32_t version; /**< 固定19，即Argon2版本0x13。 */
    uint32_t memory_kib; /**< 记录中的矩阵参数，8～策略上限。 */
    uint32_t iterations; /**< 记录中的轮数，1～策略上限。 */
    uint32_t parallelism; /**< 固定1，不在worker之外启动KDF线程。 */
    size_t encoded_length; /**< 原始PHC字节数，1～127，不含NUL。 */
} vireo_password_info_t;

/**
 * @brief 用独立随机salt生成Argon2id v19的canonical PHC存储串。
 * @param[in] policy 必需合法策略，只借用至返回。
 * @param[in] password 必需可读字节区；嵌入NUL有效，不做Unicode转换。
 * @param[in] password_length 1～policy.max_password_bytes。
 * @param[out] encoded 必需可写输出；成功写完整PHC和结尾NUL。
 * @param[in] capacity encoded实际容量，至少128字节；仅写成功结果所需前缀。
 * @param[out] encoded_length 必需独立输出；成功写入不含NUL的长度。
 * @retval VIREO_OK 完整生成并提交两个输出。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需指针为NULL或策略不合法。
 * @retval VIREO_RESULT_RANGE 密码长度或输出容量不满足合同。
 * @retval VIREO_RESULT_NO_MEMORY native计算内存申请失败。
 * @retval VIREO_RESULT_IO 安全随机源失败，不使用弱随机数降级。
 * @retval VIREO_RESULT_INTERNAL 其他native错误或内部不变量异常。
 * @note 所有输出在非OK时保持；输入/输出及输出之间不得重叠，也不得指向errno。
 * @note 输出由caller拥有；本函数清理自身敏感临时区，不擦除caller的原密码。
 * @note thread-safe，独立输出；输入调用期间不可修改。同步昂贵运算，应在worker执行。
 *       不支持POSIX线程取消或硬期限。单次参数上限不保证进程RSS或墙钟时间。
 * @note 固定16字节随机salt/32字节tag/p=1；不记录密码或完整PHC。所有路径保持errno。
 */
vireo_result_t vireo_password_hash_create(vireo_password_policy_t const *policy,
    void const *password, size_t password_length, char *encoded, size_t capacity,
    size_t *encoded_length);

/**
 * @brief 有界检查PHC格式和耗费参数，不执行KDF、随机源或动态分配。
 * @param[in] policy 必需合法策略，只借用至返回。
 * @param[in] encoded 必需可读字节区，不要求尾NUL，禁止嵌入NUL。
 * @param[in] encoded_length 精确记录长度，1～127，不含NUL。
 * @param[out] info 必需独立输出，成功才提交整个值；不与输入/errno重叠。
 * @retval VIREO_OK 格式及单次成本获准，不证明密码正确或推荐该历史参数。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需指针为NULL或策略不合法。
 * @retval VIREO_RESULT_RANGE 长度或合法数值成本超出允许范围。
 * @retval VIREO_RESULT_PROTOCOL 格式不canonical、整数溢出或类型/版本/p不受支持。
 * @note 仅接受argon2id/v19/p1、16字节salt和32字节tag；Base64无填充且未用位为零，
 *       十进制无符号与前导零，字段固定顺序，无未知字段或尾随字节。
 *       允许旧记录m>=8、t>=1，但受策略上限限制；生成仍要求至少64MiB/3轮。
 * @note 失败保持info；先基本参数、长度，再格式，再成本。独立输出thread-safe，
 *       输入只借至返回且不可并发修改。无生命周期资源；所有路径保持errno。
 */
vireo_result_t vireo_password_hash_inspect(vireo_password_policy_t const *policy,
    char const *encoded, size_t encoded_length, vireo_password_info_t *info);

/**
 * @brief 先检查记录，再在获准成本下校验密码，使用安全的tag比较。
 * @param[in] policy 必需合法策略，只借用至返回。
 * @param[in] password 必需可读密码字节区，嵌入NUL有效。
 * @param[in] password_length 1～policy.max_password_bytes。
 * @param[in] encoded 必需只读PHC字节区，不要求尾NUL，调用期间不可修改。
 * @param[in] encoded_length 精确记录长度，1～127，不含NUL。
 * @param[out] matches 必需独立输出；OK时true为匹配、false为正常完成但密码错误。
 * @retval VIREO_OK 校验完成，无论密码匹配与否。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需指针为NULL或策略不合法。
 * @retval VIREO_RESULT_RANGE 密码/PHC长度或记录成本超限。
 * @retval VIREO_RESULT_PROTOCOL PHC格式、整数、类型/版本/p不符合inspect合同。
 * @retval VIREO_RESULT_NO_MEMORY native计算内存申请失败。
 * @retval VIREO_RESULT_INTERNAL 其他native错误。
 * @note 非OK保持matches，拒绝的记录不执行KDF；先基本参数、全部长度、格式再成本。
 *       输入/输出禁止重叠，输出不得指向errno；所有路径保持errno。
 * @note 借用与清理、thread-safe、同步worker运算及取消限制同create；不自动重哈希。
 *       内部诊断分类由未来业务层统一映射对外登录失败，不查询账户或数据库。
 */
vireo_result_t vireo_password_hash_verify(vireo_password_policy_t const *policy,
    void const *password, size_t password_length, char const *encoded,
    size_t encoded_length, bool *matches);

#endif
