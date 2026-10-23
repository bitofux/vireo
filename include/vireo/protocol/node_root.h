/*
 * PROJECT : VIREO
 * FILE    : node_root.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-22
 * BRIEF   : NODE_ROOT根发现完整帧的纯编解码，不负责身份认证或资源访问。
 */
#ifndef VIREO_PROTOCOL_NODE_ROOT_H
#define VIREO_PROTOCOL_NODE_ROOT_H
#include <stddef.h>
#include <stdint.h>
#include <vireo/base/result.h>
#include <vireo/protocol/protocol.h>

/* 命令局部schema；与STAT的NODE_ID数值一致，不依赖STAT或auth schema。 */
#define VIREO_NODE_ROOT_TLV_NODE_ID UINT16_C(0x0401)
/** @brief 请求body为空，不提交身份或节点选择器。 */
#define VIREO_NODE_ROOT_REQUEST_BODY_SIZE ((size_t)0)
/** @brief 完整请求固定32字节，仅含公共包头。 */
#define VIREO_NODE_ROOT_REQUEST_FRAME_SIZE ((size_t)32)
/** @brief 成功body恰12字节：4字节TLV头及8字节非零根ID；错误body为0。 */
#define VIREO_NODE_ROOT_RESPONSE_BODY_MAX ((size_t)12)
/** @brief 成功完整响应44字节，非OK完整响应32字节。 */
#define VIREO_NODE_ROOT_RESPONSE_FRAME_MAX ((size_t)44)

/** @brief 独立请求值；无user、持久Session或资源选择器，不是wire布局。 */
typedef struct vireo_node_root_request {
    uint32_t sequence; /**< 非零关联号，不是权限凭据。 */
    uint32_t session_handle; /**< 当前连接原短句柄；0语法合法，路由须拒绝未认证。 */
} vireo_node_root_request_t;

/** @brief 独立响应值；成功仅提供本次授权读取的根ID。 */
typedef struct vireo_node_root_response {
    vireo_status_t status; /**< 下列response_encode列出的14状态之一，不能由内部rc强转。 */
    uint32_t sequence; /**< 原请求非零序号；caller仍须匹配在途请求。 */
    uint32_t session_handle; /**< OK回显原请求非零句柄，非OK必须0。 */
    uint64_t root_node_id; /**< OK非零真实根ID，非OK为0；不是权限票据。 */
} vireo_node_root_response_t;

/** @brief 本地去敏诊断；不发送到wire，不含身份、SQL或输入片段。 */
typedef enum vireo_node_root_issue {
    VIREO_NODE_ROOT_ISSUE_NONE = 0, /**< 本次没有拒绝诊断；入口重置及完整成功使用。 */
    VIREO_NODE_ROOT_ISSUE_HEADER = 1, /**< 过短/公共framing或方向基础规则失败。 */
    VIREO_NODE_ROOT_ISSUE_ENVELOPE = 2, /**< 长度上限/命令/精确flags/状态/handle约束。 */
    VIREO_NODE_ROOT_ISSUE_CRC = 3, /**< CRC不匹配。 */
    VIREO_NODE_ROOT_ISSUE_FIELDS = 4, /**< TLV未知/缺少/重复/截断/长度错误。 */
    VIREO_NODE_ROOT_ISSUE_VALUE = 5 /**< 成功响应根ID为0。 */
} vireo_node_root_issue_t;

/**
 * @brief 编码恰32字节空body的NODE_ROOT请求完整帧
 *
 * @param[in] value
 *     必需独立只读值，sequence非零，handle为原u32且允许0。
 * @param[out] wire
 *     必需capacity字节可写区；失败全部保持，成功仅写帧长。
 * @param[in] capacity
 *     真实容量，不足32亦可传入以报告RANGE。
 * @param[out] out_size
 *     必需独立地址；仅成功写32，失败保持。
 *
 * @retval VIREO_OK
 *     完整帧发布，flags/status/task均0，CRC正确。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL或宿主值非法，先于容量判定。
 * @retval VIREO_RESULT_RANGE
 *     值合法但容量不足。
 * @return codec依赖意外失败沿原rc且不发布部分输出。
 *
 * @note 所有地址有效对齐互不重叠且不指向errno，借用至返回；不保存指针或接管资源。
 *     最多44字节局部暂存，无分配/I/O/锁/采时/重试，保持errno。
 *     独立对象可并发，同一输出须外部同步；不验证登录或发送报文。
 */
vireo_result_t vireo_node_root_request_encode(const vireo_node_root_request_t *value,
    unsigned char *wire, size_t capacity, size_t *out_size);

/**
 * @brief 校验恰好一帧请求，成功发布独立数值，不构造可信actor
 *
 * @param[in] wire
 *     必需稳定只读wire_size字节，仅借至返回；长度0可报告协议错误。
 * @param[in] wire_size
 *     实际帧长，成功必须32，不接受body或尾随帧。
 * @param[out] out
 *     必需独立对象，仅成功修改；失败保留旧字节含padding。
 * @param[out] issue
 *     必需独立地址；非NULL时入口置NONE，格式失败写诊断。
 *
 * @retval VIREO_OK
 *     header/包络/CRC通过，handle0亦可解析，仍须路由认证。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL；非NULL issue仍重置。
 * @retval VIREO_RESULT_PROTOCOL
 *     长度/header/包络/CRC错误，out保持。
 *
 * @note 所有地址有效对齐独立且不指向errno；先核有界帧长再处理内容。
 *     不保存借用，无分配/I/O/锁/认证，保持errno；独立对象可并发。
 */
vireo_result_t vireo_node_root_request_decode(const unsigned char *wire, size_t wire_size,
    vireo_node_root_request_t *out, vireo_node_root_issue_t *issue);

/**
 * @brief 编码NODE_ROOT响应：OK为44字节单TLV，非OK为32字节空body
 *
 * @param[in] value
 *     必需独立只读值；sequence非零，状态在下述14项内。
 * @param[out] wire
 *     必需capacity字节独立可写区，失败全部保持。
 * @param[in] capacity
 *     真实容量；成功完整帧32或44字节。
 * @param[out] out_size
 *     必需独立地址，仅成功写本次帧长，失败保持。
 *
 * @retval VIREO_OK
 *     完整CRC帧发布，flags仅RESPONSE，task为0。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL或值/状态/成员关系非法。
 * @retval VIREO_RESULT_RANGE
 *     值合法但容量不足，先校验值再核容量。
 * @return codec/TLV依赖意外失败沿原rc，wire/out_size保持。
 *
 * @note OK要求handle及root_node_id均非零；非OK两者均0，不检查padding。
 *     状态：OK/BAD_REQUEST/UNSUPPORTED/CRC_MISMATCH/BODY_TOO_LARGE/INVALID_FLAGS/
 *     DUPLICATE_REQUEST/RATE_LIMITED/UNAUTHORIZED/BUSY/INTERNAL_ERROR/TIMEOUT/
 *     OVERLOADED/UNAVAILABLE。缺根内部错误不编码为NOT_FOUND或成功ID0。
 * @note 所有地址有效对齐互不重叠且不指向errno，借用至返回；最多44字节暂存，
 *     无分配/I/O/锁/采时/重试，保持errno，独立对象可并发，同输出外部同步。
 */
vireo_result_t vireo_node_root_response_encode(const vireo_node_root_response_t *value,
    unsigned char *wire, size_t capacity, size_t *out_size);

/**
 * @brief 完整校验响应并发布独立值；不匹配在途请求或证明根权限
 *
 * @param[in] wire
 *     必需稳定只读wire_size字节，借用至返回，不保存指针。
 * @param[in] wire_size
 *     实际完整帧长，允许传入任意长度以检查，成功仅32或44。
 * @param[out] out
 *     必需独立对象，仅成功修改；失败保持旧字节含padding。
 * @param[out] issue
 *     必需独立诊断，非NULL入口重置NONE，协议失败给本地类别。
 *
 * @retval VIREO_OK
 *     满足response_encode合同；合法非OK亦返回OK，由caller处理status。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL，非NULL issue仍重置。
 * @retval VIREO_RESULT_PROTOCOL
 *     有界长/header/包络/CRC/TLV/零根ID错误，out保持。
 *
 * @note 先核有界长度，再公共头/包络/CRC/字段/取值，完整消费，未知字段拒绝。
 *     非OK的root为0且handle0不是解绑指令；caller核command/seq/成功handle关联。
 *     根ID不证明以后授权或CAS存在；无Session修改、I/O/分配/锁，保持errno。
 *     全部地址有效对齐独立且不指向errno；独立对象可并发，同输出外部同步。
 */
vireo_result_t vireo_node_root_response_decode(const unsigned char *wire, size_t wire_size,
    vireo_node_root_response_t *out, vireo_node_root_issue_t *issue);
#endif
