/* PROJECT: VIREO; FILE: auth_response.h; AUTHOR: bitofux; DATE: 2026-10-20.
 * 四命令完整响应schema；只依赖protocol，不依赖service/net。 */
#ifndef VIREO_PROTOCOL_AUTH_RESPONSE_H
#define VIREO_PROTOCOL_AUTH_RESPONSE_H
#include <vireo/protocol/protocol.h>
#include <vireo/base/result.h>
#include <stddef.h>
#define VIREO_AUTH_RESPONSE_FRAME_MAX ((size_t)104)
#define VIREO_AUTH_RESPONSE_TOKEN_BYTES ((size_t)32)
/* 以下编号仅属于响应body；整数值均大端。未知/重复/缺失字段拒绝。 */
#define VIREO_AUTH_RESPONSE_USER_ID UINT16_C(1)
#define VIREO_AUTH_RESPONSE_ROOT_NODE_ID UINT16_C(2)
#define VIREO_AUTH_RESPONSE_TOKEN UINT16_C(3)
#define VIREO_AUTH_RESPONSE_ISSUED_AT_MS UINT16_C(4)
#define VIREO_AUTH_RESPONSE_EXPIRES_AT_MS UINT16_C(5)
/** 独立拥有型wire语义值，含敏感bearer；用完clear，不可memcpy上网/日志。 */
typedef struct vireo_auth_response {
    vireo_command_t command; /**< 四认证命令。 */
    vireo_status_t status; /**< 已注册状态；非OK必须空body/handle。 */
    uint32_t sequence; /**< 原请求非零标签。 */
    uint32_t session_handle; /**< LOGIN/RESUME OK非零；不是凭据或SQL session ID。 */
    uint64_t user_id; /**< REGISTER/LOGIN/RESUME OK时非零，LOGOUT为0。 */
    uint64_t root_node_id; /**< 仅REGISTER OK非零。 */
    uint64_t issued_at_ms; /**< LOGIN/RESUME OK有效，0合法。 */
    uint64_t expires_at_ms; /**< LOGIN/RESUME OK严格大于issued。 */
    unsigned char token[32]; /**< 仅LOGIN OK有效，全部位模式合法。 */
} vireo_auth_response_t;
/**
 * @brief 编码完整有限响应帧，失败保持wire及out_size，所有临时token返回前擦除
 * @param[in] value 必需独立只读值，所有无效分支字段必须零；短借不保存。
 * @param[out] wire 必需真实可写capacity字节，成功复制32/56/68/104字节前缀。
 * @param[in] capacity 实际缓冲大小，可小于104但须容纳本次整帧，无申请。
 * @param[out] out_size 必需独立长度，只成功覆盖。
 * @return OK；NULL/畸形值INVALID_ARGUMENT；容量不足RANGE；其他codec/TLV错误透传。
 * @note REGISTER OK需USER/ROOT两个u64；LOGIN OK需USER/TOKEN/ISSUED/EXPIRES。
 *       RESUME OK只有USER/ISSUED/EXPIRES，不重发token；LOGOUT OK空body/handle0。
 *       RESPONSE flags固定、task_handle0；非OK空body/handles0。CRC覆盖全帧。
 *       只借到返回，所有地址/errno独立不重叠。无I/O/分配，保持errno，独立值可并发。
 */
vireo_result_t vireo_auth_response_encode(vireo_auth_response_t const *value,
    unsigned char *wire, size_t capacity, size_t *out_size);
/**
 * @brief 校验精确整帧、CRC和schema后产生独立拥有型结果，失败保持整个旧out
 * @param[in] wire 必需稳定可读size字节，不保存借用；含token时caller另行擦输入。
 * @param[in] size 必须恰为整帧大小且<=104，不接受尾随字节。
 * @param[out] out 必需独占值，caller先处理旧token义务；成功才覆盖。
 * @return OK；NULL为INVALID_ARGUMENT；畸形header/CRC/schema/字段配对为PROTOCOL。
 * @note 无分配/I/O；输入输出/errno独立；局部候选统一擦，保持errno，独立存储可并发。
 */
vireo_result_t vireo_auth_response_decode(unsigned char const *wire, size_t size,
    vireo_auth_response_t *out);
/** 独占非NULL值整个安全擦除，重复OK；NULL为INVALID_ARGUMENT。无I/O，保持errno。 */
vireo_result_t vireo_auth_response_clear(vireo_auth_response_t *value);
#endif
