/* PROJECT : VIREO; AUTHOR : bitofux; DATE : 2026-10-22;
 * BRIEF : 044-06已采用的分页token与LIST服务合同。 */
#ifndef VIREO_SECURITY_PAGE_TOKEN_H
#define VIREO_SECURITY_PAGE_TOKEN_H
#include <stdint.h>
#include <vireo/base/result.h>
#define VIREO_PAGE_TOKEN_BYTES 96
#define VIREO_PAGE_TOKEN_TTL_MS UINT64_C(600000)
/** @brief 不可变opaque密钥owner；不代表用户/目录权限，借用结束后才能销毁。 */
typedef struct vireo_page_token_key vireo_page_token_key_t;
/** @brief caller拥有的独立不透明值，禁止记录token字节；无指针或wire身份凭据。 */
typedef struct vireo_page_token {
    unsigned char bytes[VIREO_PAGE_TOKEN_BYTES];
} vireo_page_token_t;
/** @brief 签名绑定的上下文；actor须由可信服务生产，普通值不证明身份。 */
typedef struct vireo_page_token_context {
    uint64_t user_id;      /**< 非零持久用户，不能由客户端直接指定。 */
    uint64_t session_id;   /**< 非零持久session，不是短handle。 */
    uint64_t directory_id; /**< 非零资源选择器，不授予目录权限。 */
    uint16_t page_size;    /**< 显式1..64；绑定v1 ID升序/ACTIVE直接孩子策略。 */
} vireo_page_token_context_t;
/** @brief 完整验过后才发布的独立声明，非C wire布局。 */
typedef struct vireo_page_token_claims {
    vireo_page_token_context_t context; /**< 与签发/验证要求的上下文完全匹配。 */
    uint64_t after_id; /**< 非零，最后一条实际交付ID；允许UINT64_MAX，不作+1。 */
    uint64_t issued_at_ms;  /**< 第一枚token的UTC毫秒，续页不刷新。 */
    uint64_t expires_at_ms; /**< issued+600000，受检加法；消费issued<=now<expires。 */
} vireo_page_token_claims_t;
/**
 * @brief 创建独立进程页token密钥owner，CSPRNG32字节secret/独立非零u32 key_id
 * @param[out] out 必需独立有效地址，*out必需NULL，仅成功发布owner；失败原值保持。
 * @retval VIREO_OK owner已创建，内部只读HMAC算法与secret保活至destroy。
 * @retval VIREO_RESULT_INVALID_ARGUMENT out为NULL或*out非NULL。
 * @retval VIREO_RESULT_NO_MEMORY owner分配失败。
 * @retval VIREO_RESULT_IO 任一CSPRNG失败或key_id为0；不降级、不自动重试。
 * @retval VIREO_RESULT_INTERNAL OpenSSL3 HMAC provider获取失败。
 * @note 失败逆序释放owner/算法并cleanse秘密临时区，out不改，无秘密日志。
 * 可能分配或阻塞，无硬期限；适合装配线程，不支持POSIX异步取消/longjmp。
 * 地址有效对齐、不指向errno；保持errno；独立输出可并发，共享地址外部同步。
 * 不持久化/轮换/复用登录密钥；每次进程启动创建新键，fork子服务须另建。
 */
vireo_result_t vireo_page_token_key_create(vireo_page_token_key_t **out);
/**
 * @brief 在所有借用结束后擦除secret、释放算法和owner并置NULL
 * @param[in,out] key 必需有效独占owner地址；*key为NULL时幂等成功。
 * @retval VIREO_OK 当前owner已消费且*key=NULL，或原本NULL。
 * @retval VIREO_RESULT_INVALID_ARGUMENT key地址NULL，其他输出不改。
 * @note 必须先停止接纳并等待所有sign/verify/服务借用结束；无内部引用计数。
 * 不能并发借用/销毁，不接管其他key副本；调用方副本/core dump不承诺清除。
 * 保持errno，无SQL/网络/重试，地址有效对齐且不指向errno。
 */
vireo_result_t vireo_page_token_key_destroy(vireo_page_token_key_t **key);
/**
 * @brief 用独立HMAC-SHA256签发恰好96字节token；不查数据库或采时
 * @param[in] key 必需存活不变owner，借至返回并由caller保活。
 * @param[in] claims 必需独立只读完整声明，ID非零、页1..64、合法非溢出TTL。
 * @param[in] now_ms 可信UTC毫秒判断点，须issued<=now<expires；不保证返回后仍有效。
 * @param[out] out 必需独立token，只有完整成功修改，失败保持全部字节。
 * @retval VIREO_OK version1/保留零/key_id/大端payload及32字节MAC完整发布。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL或宿主context/after/非溢出TTL关系非法。
 * @retval VIREO_RESULT_OVERFLOW issued+TTL不可表示，out保持。
 * @retval VIREO_RESULT_PROTOCOL 声明结构合法但now不在时间窗口，out保持。
 * @retval VIREO_RESULT_NO_MEMORY 每次独立EVP_MAC_CTX分配失败。
 * @retval VIREO_RESULT_INTERNAL crypto初始化/update/final或输出长度失败。
 * @note MAC输入domain为ASCII vireo/node-list-page/v1加一个NUL共24字节，随后64字节payload。
 * payload偏移：version0/flags1/reserved2/key_id4/user8/session16/dir24/after32/page40/
 * reserved42..47/issued48/expires56；MAC64..95。无加密、权限、快照或单次消费承诺。
 * 每次ctx独立，所有路径释放/擦除临时秘密，无敏感日志；可分配/阻塞，无硬期限。
 * 地址有效对齐、互不重叠且不指向errno，借至返回，无借用逸出；保持errno。
 * 只读key可并发借，独立输出可并发，共同输出外部同步，不支持异步取消/longjmp。
 */
vireo_result_t vireo_page_token_sign(const vireo_page_token_key_t *key,
                                     const vireo_page_token_claims_t *claims, uint64_t now_ms,
                                     vireo_page_token_t *out);
/**
 * @brief 验MAC和完整上下文/版本/保留/时间关系后发布claims，不证明持久授权
 * @param[in] key 必需存活不变owner，caller保活，借至返回。
 * @param[in] context 必需可信独立只读上下文，三个ID非零，page_size1..64。
 * @param[in] token 必需完整96字节值；任意字节模式可作为待验输入。
 * @param[in] now_ms 可信UTC毫秒判断点，不在内部采时。
 * @param[out] out 必需独立claims，仅完整成功发布；失败保留包含padding的原对象。
 * @retval VIREO_OK 验证完整，out的context与要求一致；后续仍须重新持久授权。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL或宿主context非法。
 * @retval VIREO_RESULT_PROTOCOL
 * MAC、version/flags/reserved/key_id、上下文、after、TTL/溢出或时间不合。
 * @retval VIREO_RESULT_NO_MEMORY 每次EVP_MAC_CTX分配失败。
 * @retval VIREO_RESULT_INTERNAL crypto初始化/update/final或长度失败。
 * @note 先计算MAC并用固定32字节CRYPTO_memcmp比较，再校全部字段，只合并坏token。
 * 仅MAC比较固定长度，不承诺整函数恒时；无错误文本、凭据日志或SQL。
 * 参数/地址/借用/线程/errno/ctx清理/阻塞/取消规则同sign；out失败保持。
 * token可重放，同session RESUME不绑短handle；新session/新key失效，不提供跨页快照。
 */
vireo_result_t vireo_page_token_verify(const vireo_page_token_key_t *key,
                                       const vireo_page_token_context_t *context,
                                       const vireo_page_token_t *token, uint64_t now_ms,
                                       vireo_page_token_claims_t *out);
#endif
