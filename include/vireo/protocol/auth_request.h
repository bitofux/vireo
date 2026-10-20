/* PROJECT: VIREO — 四个认证命令完整请求帧的借用解析。 */
#ifndef VIREO_PROTOCOL_AUTH_REQUEST_H
#define VIREO_PROTOCOL_AUTH_REQUEST_H

#include <stddef.h>
#include <stdint.h>
#include <vireo/base/result.h>
#include <vireo/protocol/protocol.h>

/* v1 业务 TLV 注册：不同于既有诊断保留区 0xF001..0xF003。 */
#define VIREO_AUTH_TLV_USERNAME UINT16_C(0x0001)
#define VIREO_AUTH_TLV_PASSWORD UINT16_C(0x0002)
#define VIREO_AUTH_TLV_DEVICE UINT16_C(0x0003)
#define VIREO_AUTH_TLV_SESSION_TOKEN UINT16_C(0x0004)
#define VIREO_AUTH_RESUME_BODY_MAX ((size_t)36)
#define VIREO_AUTH_LOGOUT_BODY_MAX ((size_t)0)
#define VIREO_AUTH_REQUEST_USERNAME_MIN ((size_t)3)
#define VIREO_AUTH_REQUEST_USERNAME_MAX ((size_t)32)
#define VIREO_AUTH_REQUEST_PASSWORD_MIN ((size_t)8)
#define VIREO_AUTH_REQUEST_PASSWORD_MAX ((size_t)64)
#define VIREO_AUTH_REQUEST_DEVICE_SIZE ((size_t)16)
#define VIREO_AUTH_REGISTER_BODY_MAX ((size_t)104)
#define VIREO_AUTH_LOGIN_BODY_MAX ((size_t)124)
#define VIREO_AUTH_REQUEST_FRAME_MAX ((size_t)156)

/** 进程内分类，不直接转换为 wire status；不包含输入内容。 */
typedef enum vireo_auth_request_issue {
    VIREO_AUTH_REQUEST_ISSUE_NONE = 0,
    VIREO_AUTH_REQUEST_ISSUE_HEADER = 1, /**< 固定 framing 或请求基础语义。 */
    VIREO_AUTH_REQUEST_ISSUE_ENVELOPE = 2, /**< 命令、flags、handles 或精确帧长。 */
    VIREO_AUTH_REQUEST_ISSUE_CRC = 3, /**< CRC 校验失败。 */
    VIREO_AUTH_REQUEST_ISSUE_FIELDS = 4, /**< TLV 截断、未知、重复、缺项或长度错误。 */
    VIREO_AUTH_REQUEST_ISSUE_USERNAME = 5, /**< 用户名包含非字母/数字/下划线。 */
    VIREO_AUTH_REQUEST_ISSUE_PASSWORD = 6 /**< 密码包含 0x21..0x7e 之外字节。 */
} vireo_auth_request_issue_t;

/** 宿主语义视图，不能直接序列化；所有指针借用原始完整帧。 */
typedef struct vireo_auth_request_view {
    vireo_command_t command; /**< REGISTER/LOGIN/LOGOUT/SESSION_RESUME。 */
    uint32_t sequence; /**< 非零请求序号；不证明身份。 */
    uint8_t const *username; /**< 未归一化、无 NUL 结尾保证的原用户名。 */
    size_t username_size; /**< REGISTER/LOGIN为3..32，其余0。 */
    uint8_t const *password; /**< 敏感原始密码；不允许日志记录。 */
    size_t password_size; /**< REGISTER/LOGIN为8..64，其余0。 */
    uint8_t const *device; /**< LOGIN 恰好 16 字节；其他命令为 NULL。 */
    uint32_t session_handle; /**< 仅LOGOUT非零，仍须完整连接租约验证。 */
    uint8_t const *token; /**< 仅RESUME借用32字节秘密，任意位模式合法。 */
} vireo_auth_request_view_t;

/**
 * @brief 验证恰好一个认证 请求帧，成功后一次发布借用视图
 * @param[in] wire 非 NULL，指向 wire_size 个有效只读字节；允许 wire_size 为零。
 * @param[in] wire_size 实际完整帧长，不含后续帧；非法/不完整帧返回 PROTOCOL。
 * @param[out] out_view 非 NULL；只在成功时修改，包括失败时保持 padding 字节。
 * @param[out] out_issue 非 NULL；每次先置 NONE，协议失败时给出不含秘密的分类。
 * @retval VIREO_OK header、CRC、精确帧长、命令级 schema 和 ASCII 规则全部通过。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 任一指针为 NULL；非 NULL issue 仍置 NONE。
 * @retval VIREO_RESULT_PROTOCOL 不满足请求协议；out_view 整值保持。
 * @note 规则：flags/status/task_handle 全零，sequence 非零；
 *       LOGOUT为32字节、handle非零、空body；其余handle零。RESUME为68字节、
 *       只含type4的32字节token（全部位模式合法），不含密码/设备。
 *       REGISTER 只含 USERNAME/PASSWORD，LOGIN 再含 DEVICE；字段任意顺序、
 *       恰好各一次，拒绝未知字段；用户名为 ASCII 字母/数字/下划线，
 *       密码为 0x21..0x7e，DEVICE 的全部位模式均合法。
 * @note 所有权与生命周期：不分配、不复制密码/token、不接管或保存输入；输出指针
 *       仅在原帧未被释放、覆盖、擦除或移动期间有效。调用者负责帧的秘密擦除，
 *       不得跨 connection 消费/缓冲区变更保留视图；worker 应重新解析其自有 task。
 * @note 别名：输出对象之间、输出与输入不得重叠，输出不得指向 errno；
 *       非 NULL 指针须满足真实对象边界。
 * @note 线程安全：独立输出可并发使用；输入借用期间不得被并发修改。
 * @note errno：保持入口值；不执行 I/O、KDF、准入扣费、认证或 Session 绑定。
 * @warning CRC 不提供身份认证；客户端设备标签不可信，peer IP 必须另从连接获取。
 */
vireo_result_t vireo_auth_request_decode(uint8_t const *wire, size_t wire_size,
                                       vireo_auth_request_view_t *out_view,
                                       vireo_auth_request_issue_t *out_issue);

#endif /* VIREO_PROTOCOL_AUTH_REQUEST_H */
