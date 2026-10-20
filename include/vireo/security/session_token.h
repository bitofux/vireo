/* Session凭据密码设施：同步固定值运算，不拥有Session或网络资源。 */
#ifndef VIREO_SECURITY_SESSION_TOKEN_H
#define VIREO_SECURITY_SESSION_TOKEN_H

#include <limits.h>
#include <stdbool.h>
#include <vireo/base/result.h>

#if CHAR_BIT != 8
#error "vireo_session_token requires 8-bit bytes"
#endif

/** @brief 原始bearer凭据字节数；不是字符串长度。 */
#define VIREO_SESSION_TOKEN_BYTES 32
/** @brief 固定v1 SHA-256摘要字节数。 */
#define VIREO_SESSION_TOKEN_DIGEST_BYTES 32

/** @brief caller拥有的普通可复制秘密值；所有位模式（包括全零）均合法。 */
typedef struct vireo_session_token {
    unsigned char bytes[VIREO_SESSION_TOKEN_BYTES]; /**< 完整32字节秘密，不含身份或有效性标记。 */
} vireo_session_token_t;

/** @brief caller拥有的服务端摘要值；不能作为客户端bearer凭据或授权证明。 */
typedef struct vireo_session_token_digest {
    unsigned char bytes[VIREO_SESSION_TOKEN_DIGEST_BYTES]; /**< 固定v1存储/比较值。 */
} vireo_session_token_digest_t;

/**
 * @brief 安全随机生成token并计算摘要，全部成功后才写两个输出。
 * @param[out] token 必需、正确对齐且独占的可写输出，借用至返回。
 * @param[out] digest 必需独立可写输出，不与token或errno重叠。
 * @retval VIREO_OK 两个输出完整写入；不承诺跨线程原子发布。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 任一必需指针为NULL。
 * @retval VIREO_RESULT_IO CSPRNG失败；不弱随机降级或自动重试。
 * @retval VIREO_RESULT_NO_MEMORY 摘要上下文分配失败。
 * @retval VIREO_RESULT_INTERNAL 摘要执行或输出长度异常。
 * @note 失败保持两个输出，所有路径保持errno，无敏感日志。内部秘密临时区显式清理。
 * @note 可能分配、初始化随机源或阻塞，适合worker/允许阻塞的装配线程；无硬期限，
 *       不支持POSIX异步取消。独立输出thread-safe，共享值须由caller同步。
 * @note 普通C值可被复制；只发放一次、事务、撤销和全部副本清理属于调用层。
 */
vireo_result_t vireo_session_token_generate(
    vireo_session_token_t *token, vireo_session_token_digest_t *digest);

/**
 * @brief 计算SHA-256(domain[23] || token.bytes[32])，成功后才提交摘要。
 * @param[in] token 必需只读、正确对齐的完整值，借用期间不得修改。
 * @param[out] digest 必需独占输出，不与输入或errno重叠。
 * @retval VIREO_OK 已提交32字节摘要，输入保持。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 任一必需指针为NULL。
 * @retval VIREO_RESULT_NO_MEMORY 摘要上下文分配失败。
 * @retval VIREO_RESULT_INTERNAL 摘要执行或输出长度异常。
 * @note domain为ASCII "vireo/session-token/v1"加恰好一个NUL，共23字节；消息共55字节。
 *       这是持久摘要v1合同，未来升级须明确兼容政策；不定义ABI、文本或wire编码。
 * @note 失败保持输出，所有路径保持errno；输入全部32字节有效，包括NUL或全零。
 *       同步分配/计算、线程/借用/取消限制同generate；不查Session过期或撤销状态。
 */
vireo_result_t vireo_session_token_digest(
    vireo_session_token_t const *token, vireo_session_token_digest_t *digest);

/**
 * @brief 使用固定32字节CRYPTO_memcmp比较摘要。
 * @param[in] left 必需正确对齐只读摘要，借用至返回。
 * @param[in] right 必需正确对齐只读摘要，允许与left为同一对象。
 * @param[out] matches 必需独占bool输出，不与输入或errno重叠。
 * @retval VIREO_OK 已写true（相同）或false（不同），两者均为成功比较。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 任一必需指针为NULL，保持matches。
 * @note 无堆分配；所有路径保持errno。独立输出thread-safe，输入借用期间不得修改。
 *       相等不代表Session未过期、未撤销或账户已授权。
 */
vireo_result_t vireo_session_token_digest_equal(vireo_session_token_digest_t const *left,
    vireo_session_token_digest_t const *right, bool *matches);

/**
 * @brief 用OPENSSL_cleanse擦除当前token.bytes；可重复调用，无堆分配。
 * @param[in,out] token 必需正确对齐、独占可写值，借用至返回，不与errno重叠。
 * @retval VIREO_OK 当前32字节归零，不free、不处理其他副本。
 * @retval VIREO_RESULT_INVALID_ARGUMENT token为NULL。
 * @note 所有路径保持errno；共享值须外部同步，不能并发读取或摘要。
 *       全零仍是合法token，不表示数据库撤销；本函数不等于logout。
 */
vireo_result_t vireo_session_token_clear(vireo_session_token_t *token);

#endif
