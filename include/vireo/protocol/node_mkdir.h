/*
 * PROJECT : VIREO
 * FILE    : node_mkdir.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-23
 * BRIEF   : NODE_MKDIR完整帧纯编解码；不执行NFC、认证或创建事务。
 */
#ifndef VIREO_PROTOCOL_NODE_MKDIR_H
#define VIREO_PROTOCOL_NODE_MKDIR_H
#include <stddef.h>
#include <stdint.h>
#include <vireo/base/result.h>
#include <vireo/protocol/protocol.h>

/** @brief 请求局部父ID，与STAT的PARENT_ID数值兼容。 */
#define VIREO_NODE_MKDIR_TLV_PARENT_ID UINT16_C(0x0402)
/** @brief 请求单段UTF-8名字，不带尾NUL。 */
#define VIREO_NODE_MKDIR_TLV_NAME UINT16_C(0x0403)
/** @brief 成功响应原创建节点ID。 */
#define VIREO_NODE_MKDIR_TLV_NODE_ID UINT16_C(0x0401)
/** @brief 16字节持久逻辑操作键；不等审计request_id或sequence。 */
#define VIREO_NODE_MKDIR_TLV_IDEMPOTENCY_KEY UINT16_C(0x0420)
/** @brief 名字按字节计数，不按Unicode字符数。 */
#define VIREO_NODE_MKDIR_NAME_CAPACITY ((size_t)255)
/** @brief 幂等键固定16字节，至少一字节非零。 */
#define VIREO_NODE_MKDIR_KEY_SIZE ((size_t)16)
/** @brief 请求body为父TLV12、名字TLV5..259、键TLV20，共37..291字节。 */
#define VIREO_NODE_MKDIR_REQUEST_BODY_MIN ((size_t)37)
#define VIREO_NODE_MKDIR_REQUEST_BODY_MAX ((size_t)291)
/** @brief 完整请求32字节头加body，69..323字节。 */
#define VIREO_NODE_MKDIR_REQUEST_FRAME_MIN ((size_t)69)
#define VIREO_NODE_MKDIR_REQUEST_FRAME_MAX ((size_t)323)
/** @brief 成功body包含NODE_ID12与原键20；错误body0。 */
#define VIREO_NODE_MKDIR_RESPONSE_BODY_SIZE ((size_t)32)
/** @brief 成功完整响应64，错误完整响应32字节。 */
#define VIREO_NODE_MKDIR_RESPONSE_FRAME_MAX ((size_t)64)

/** @brief 按值独立请求；没有user_id/持久Session，不构成可信actor。 */
typedef struct vireo_node_mkdir_request {
    uint32_t sequence; /**< 非零本次关联号；重连重试可用新sequence。 */
    uint32_t session_handle; /**< 原连接u32句柄，0语法合法，认证由路由处理。 */
    uint64_t parent_id; /**< 非零显式父选择器，0不代表根，不证明权限。 */
    unsigned char name[VIREO_NODE_MKDIR_NAME_CAPACITY]; /**< 前name_length字节有效，无尾NUL要求。 */
    size_t name_length; /**< 1..255且为完整合法UTF-8/单段NAME；codec不执行NFC。 */
    unsigned char idempotency_key[VIREO_NODE_MKDIR_KEY_SIZE]; /**< 至少一非零；生产按用户/命令作用域持久使用。 */
} vireo_node_mkdir_request_t;

/** @brief 按值独立响应；不是COMMIT或资源清理报告。 */
typedef struct vireo_node_mkdir_response {
    vireo_status_t status; /**< response_encode列出的19状态之一。 */
    uint32_t sequence; /**< 本次请求原非零关联号，仍须caller匹配。 */
    uint32_t session_handle; /**< OK非零当前句柄，错误0不是登出指令。 */
    uint64_t node_id; /**< OK原成功创建ID；错误0；不证明该节点现在仍活动。 */
    unsigned char idempotency_key[VIREO_NODE_MKDIR_KEY_SIZE]; /**< OK原非零键，错误全部0。 */
} vireo_node_mkdir_response_t;

/** @brief 本地去敏诊断，不编码到wire或保留原始名字。 */
typedef enum vireo_node_mkdir_issue {
    VIREO_NODE_MKDIR_ISSUE_NONE = 0, /**< 入口重置与完整成功。 */
    VIREO_NODE_MKDIR_ISSUE_HEADER = 1, /**< 公共framing/方向基础验证拒绝。 */
    VIREO_NODE_MKDIR_ISSUE_ENVELOPE = 2, /**< 命令/精确flags/状态/handle或有界长度拒绝。 */
    VIREO_NODE_MKDIR_ISSUE_CRC = 3, /**< 完整精确帧CRC不匹配。 */
    VIREO_NODE_MKDIR_ISSUE_FIELDS = 4, /**< TLV未知/缺失/重复/截断/定长错误。 */
    VIREO_NODE_MKDIR_ISSUE_VALUE = 5 /**< 零父/零键/非法UTF-8或NAME/响应成员关系错误。 */
} vireo_node_mkdir_issue_t;

/**
 * @brief 编码69..323字节的NODE_MKDIR完整请求
 *
 * @param[in] value
 *     必需独立只读请求，sequence/parent非零、名字满足上述长度和NAME、键非零。
 * @param[out] wire
 *     必需capacity字节可写区，失败整个容量保持，成功只写实际帧长。
 * @param[in] capacity
 *     真实可写容量，允许不足本次帧长以报告RANGE。
 * @param[out] out_size
 *     必需独立地址，仅完整成功写实际帧长，失败保持。
 *
 * @retval VIREO_OK
 *     完整CRC帧发布，command固定0x0403，flags/status/task为0。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL或宿主值非法，先于容量检查。
 * @retval VIREO_RESULT_RANGE
 *     值合法但容量不足，输出保持。
 * @return codec/TLV依赖意外错误沿原rc且不发布部分输出。
 *
 * @note 所有地址有效、对齐、互不重叠且不指向errno，输入借至返回，不保存指针。
 *     名字不含NUL/斜杠/C0/C1且非点/双点，未用name尾部忽略，不截断或trim。
 *     本层不执行NFC、身份/授权/幂等查询或事务；编码不保证安全重试已经可用。
 *     无分配/I/O/锁/采时/重试，保持errno；独立对象可并发，同输出外部同步。
 */
vireo_result_t vireo_node_mkdir_request_encode(const vireo_node_mkdir_request_t *value,
    unsigned char *wire, size_t capacity, size_t *out_size);

/**
 * @brief 校验一个完整请求并复制独立值，不创建目录或可信身份
 *
 * @param[in] wire
 *     必需稳定只读wire_size字节，仅借至返回，不保存借用。
 * @param[in] wire_size
 *     实际帧长，成功必须69..323且精确匹配header，无尾随字节。
 * @param[out] out
 *     必需独立对象，仅成功修改；失败保留原字节含padding，成功未用name尾部为0。
 * @param[out] issue
 *     必需独立诊断；非NULL时入口置NONE，格式失败写本地类别。
 *
 * @retval VIREO_OK
 *     有界帧、header/包络/CRC/TLV/值关系通过；handle0亦可成功解析。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL；非NULL issue仍重置。
 * @retval VIREO_RESULT_PROTOCOL
 *     长度/header/包络/CRC/字段或取值拒绝，out保持。
 *
 * @note 全部地址有效对齐独立且不指向errno；先核有界长再解析，不只信header长度。
 *     三个必需单值字段可乱序，未知/重复/缺项拒绝；不执行NFC或资源权限判断。
 *     无分配/I/O/锁/重试，保持errno；独立对象可并发，同输出外部同步。
 */
vireo_result_t vireo_node_mkdir_request_decode(const unsigned char *wire, size_t wire_size,
    vireo_node_mkdir_request_t *out, vireo_node_mkdir_issue_t *issue);

/**
 * @brief 编码NODE_MKDIR响应，OK固定64字节，错误固定32字节空body
 *
 * @param[in] value
 *     必需独立只读响应，sequence非零，OK要求非零handle/node/key；错误三者为0。
 * @param[out] wire
 *     必需capacity字节独立可写区，失败整个容量保持。
 * @param[in] capacity
 *     真实可写容量，成功写本次完整32或64字节。
 * @param[out] out_size
 *     必需独立地址，仅成功写实际帧长，失败保持。
 *
 * @retval VIREO_OK
 *     完整帧发布，flags仅RESPONSE，task为0，CRC正确。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL或状态/成员关系非法，先于容量检查。
 * @retval VIREO_RESULT_RANGE
 *     值合法但容量不足，输出保持。
 * @return codec/TLV依赖意外错误沿原rc，不发布部分输出。
 *
 * @note 状态：OK/BAD_REQUEST/UNSUPPORTED/CRC_MISMATCH/BODY_TOO_LARGE/INVALID_FLAGS/
 *     DUPLICATE_REQUEST/RATE_LIMITED/UNAUTHORIZED/NOT_FOUND/ALREADY_EXISTS/INVALID_PATH/
 *     CONFLICT/BUSY/INTERNAL_ERROR/DB_ERROR/TIMEOUT/OVERLOADED/UNAVAILABLE。
 *     错误无node/key，不承诺数据库回滚；TIMEOUT可能在COMMIT后，不能换键盲重放。
 *     OK语义是原逻辑操作曾成功，不证明节点现在活动，首次与恢复结果格式一致。
 * @note 地址有效对齐独立不重叠且不指向errno；不保存借用或接管owner。
 *     无分配/I/O/锁/采时/重试，保持errno；独立对象可并发，同输出外部同步。
 */
vireo_result_t vireo_node_mkdir_response_encode(const vireo_node_mkdir_response_t *value,
    unsigned char *wire, size_t capacity, size_t *out_size);

/**
 * @brief 完整校验响应并发布独立值，不确认权限或自动重试事务
 *
 * @param[in] wire
 *     必需稳定只读wire_size字节，借至返回。
 * @param[in] wire_size
 *     实际完整帧长，成功仅32或64，精确匹配header。
 * @param[out] out
 *     必需独立对象，仅成功修改；失败保留旧字节含padding，错误node/key为0。
 * @param[out] issue
 *     必需独立诊断，非NULL入口置NONE，拒绝时提供去敏类别。
 *
 * @retval VIREO_OK
 *     满足response_encode字节/成员合同；合法非OK业务响应也返回OK。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL，非NULL issue仍重置。
 * @retval VIREO_RESULT_PROTOCOL
 *     header/有界长/包络/CRC/TLV/值关系不合法，out保持。
 *
 * @note 先核长度，再header/包络/CRC/字段/值，完整消费，字段乱序可接受。
 *     caller仍核本次command/sequence、OK handle与原键；handle0错误不改变绑定。
 *     非OK/断连不证明未提交，原键和原载荷须保留以走持久回执协议。
 *     地址独立有效对齐不指向errno；无分配/I/O/锁/重试，保持errno，独立对象可并发。
 */
vireo_result_t vireo_node_mkdir_response_decode(const unsigned char *wire, size_t wire_size,
    vireo_node_mkdir_response_t *out, vireo_node_mkdir_issue_t *issue);
#endif
