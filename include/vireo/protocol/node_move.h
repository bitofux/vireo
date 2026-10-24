/*
 * PROJECT : VIREO
 * FILE    : node_move.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-24
 * BRIEF   : NODE_MOVE完整帧纯编解码；不执行NFC、认证或移动事务。
 */
#ifndef VIREO_PROTOCOL_NODE_MOVE_H
#define VIREO_PROTOCOL_NODE_MOVE_H
#include <stddef.h>
#include <stdint.h>
#include <vireo/base/result.h>
#include <vireo/protocol/protocol.h>

/** @brief 源节点ID及成功历史结果ID，移动保持节点ID。 */
#define VIREO_NODE_MOVE_TLV_NODE_ID UINT16_C(0x0401)
/** @brief 持久逻辑操作键，和执行审计事件、sequence分别判断。 */
#define VIREO_NODE_MOVE_TLV_IDEMPOTENCY_KEY UINT16_C(0x0420)
/** @brief 显式最终父ID，不是源原父或当前目录。 */
#define VIREO_NODE_MOVE_TLV_NEW_PARENT_ID UINT16_C(0x0430)
/** @brief 显式最终单段UTF-8名字，不包含尾NUL。 */
#define VIREO_NODE_MOVE_TLV_NEW_NAME UINT16_C(0x0431)
/** @brief 新名字字节容量，不是Unicode字符个数。 */
#define VIREO_NODE_MOVE_NAME_CAPACITY ((size_t)255)
/** @brief 原始幂等键精确16字节，至少一字节非零。 */
#define VIREO_NODE_MOVE_KEY_SIZE ((size_t)16)
/** @brief 四TLV合计48+名字长度，即49..303字节body。 */
#define VIREO_NODE_MOVE_REQUEST_BODY_MIN ((size_t)49)
#define VIREO_NODE_MOVE_REQUEST_BODY_MAX ((size_t)303)
/** @brief 完整32字节头加body，即81..335字节请求。 */
#define VIREO_NODE_MOVE_REQUEST_FRAME_MIN ((size_t)81)
#define VIREO_NODE_MOVE_REQUEST_FRAME_MAX ((size_t)335)
/** @brief OK为源节点TLV12+原键TLV20；非OK为空body。 */
#define VIREO_NODE_MOVE_RESPONSE_BODY_SIZE ((size_t)32)
/** @brief OK完整64字节，非OK完整32字节。 */
#define VIREO_NODE_MOVE_RESPONSE_FRAME_MAX ((size_t)64)

/** @brief 独立按值请求，不含可信持久身份或输入帧借用。 */
typedef struct vireo_node_move_request {
    uint32_t sequence; /**< 非零本次连接关联号；重试可换sequence，不能因此换逻辑键。 */
    uint32_t session_handle; /**< 原u32短handle，0可解析，不能冒充授权。 */
    uint64_t node_id; /**< 非零源选择器；文件/目录/根及owner由业务再判断。 */
    uint64_t new_parent_id; /**< 非零最终父选择器；等于node_id语法可过，业务另判环。 */
    unsigned char new_name[VIREO_NODE_MOVE_NAME_CAPACITY]; /**< 前new_name_length字节有效，未用尾忽略。 */
    size_t new_name_length; /**< 1..255合法UTF-8/NAME；纯codec不检查NFC。 */
    unsigned char idempotency_key[VIREO_NODE_MOVE_KEY_SIZE]; /**< 非全零逻辑键，须与完整载荷稳定保留。 */
} vireo_node_move_request_t;

/** @brief 独立响应，不是当前节点快照、提交或清理报告。 */
typedef struct vireo_node_move_response {
    vireo_status_t status; /**< response_encode列出的19个允许状态之一。 */
    uint32_t sequence; /**< 本次原非零请求sequence，caller仍须关联核对。 */
    uint32_t session_handle; /**< OK为本次非零handle；非OK为0，不表示logout。 */
    uint64_t node_id; /**< OK为原成功源ID；不保证当前仍在所请求位置或仍活动。 */
    unsigned char idempotency_key[VIREO_NODE_MOVE_KEY_SIZE]; /**< OK原非零键；非OK整数组为0。 */
} vireo_node_move_response_t;

/** @brief 仅本地数值诊断，无原始名字或内部持久信息，不上wire。 */
typedef enum vireo_node_move_issue {
    VIREO_NODE_MOVE_ISSUE_NONE = 0, /**< 入口重置及完整成功。 */
    VIREO_NODE_MOVE_ISSUE_HEADER = 1, /**< 公共framing/方向基础拒绝。 */
    VIREO_NODE_MOVE_ISSUE_ENVELOPE = 2, /**< 命令/精确flags/状态/handle/task/有界长度拒绝。 */
    VIREO_NODE_MOVE_ISSUE_CRC = 3, /**< 当前完整精确帧的CRC不匹配。 */
    VIREO_NODE_MOVE_ISSUE_FIELDS = 4, /**< TLV未知/缺失/重复/截断/长度错误。 */
    VIREO_NODE_MOVE_ISSUE_VALUE = 5 /**< 零ID/零键/非法UTF-8或NAME/响应成员关系错误。 */
} vireo_node_move_issue_t;

/**
 * @brief 编码NODE_MOVE完整请求，四个必需TLV显式表示最终位置
 *
 * @param[in] value
 *     必需独立只读请求，sequence/两个ID非零，名字合法，键非零；借至返回。
 * @param[out] wire
 *     必需capacity字节独立可写区；失败整个容量保持，成功只写实际帧长。
 * @param[in] capacity
 *     真实可写容量；可小于本次帧长以报告RANGE。
 * @param[out] out_size
 *     必需独立输出，仅完整成功写81..335的实际长度，失败保持。
 *
 * @retval VIREO_OK
 *     完整CRC帧发布，command=0x0405，flags/status/task为0，TLV按type升序。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL或宿主值非法，先于容量判断。
 * @retval VIREO_RESULT_RANGE
 *     宿主值合法但容量不足，输出保持。
 * @return codec/TLV依赖意外错误沿其rc，不发布部分帧。
 *
 * @note 名字拒绝NUL、斜杠、C0/C1控制字符及完整点/双点；无trim、截断或NFC转换。
 *     source与parent相等语法合法；不核源/父owner、根、类型、环或数据库幂等事实。
 * @note 全部地址有效对齐互不重叠且不指向errno；短借不保存地址，无owner交接。
 *     无分配/I/O/锁/采时/重试，保持errno；独立对象可并发，同输出外部同步。
 */
vireo_result_t vireo_node_move_request_encode(const vireo_node_move_request_t *value,
    unsigned char *wire, size_t capacity, size_t *out_size);

/**
 * @brief 完整校验一个请求帧并复制独立值，不执行移动或认证
 *
 * @param[in] wire
 *     必需稳定只读wire_size字节，借至返回，不保存输入视图。
 * @param[in] wire_size
 *     实际帧长；成功须81..335且与header精确一致，无尾随帧/字节。
 * @param[out] out
 *     必需独立独占对象，仅完整成功写；失败保留原字节含padding，成功未用名字尾归零。
 * @param[out] issue
 *     必需独立诊断；非NULL时入口重置NONE，格式失败写相应本地类别。
 *
 * @retval VIREO_OK
 *     header/包络/CRC/四TLV/值通过；handle0和两个ID相等均可语法通过。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL；非NULL issue仍重置。
 * @retval VIREO_RESULT_PROTOCOL
 *     帧长/header/包络/CRC/字段或取值错误，out保持。
 *
 * @note 先核实际有界长度，再header/包络/CRC/字段/值；未知/重复/缺少字段拒绝，允许乱序。
 *     不执行NFC/授权/根保护/防环/覆盖检查或事务；解析成功不代表请求可执行。
 * @note 地址有效对齐独立不重叠且不指向errno；无借用逸出、分配/I/O/锁/重试。
 *     保持errno，独立对象可并发，同输出外部同步。
 */
vireo_result_t vireo_node_move_request_decode(const unsigned char *wire, size_t wire_size,
    vireo_node_move_request_t *out, vireo_node_move_issue_t *issue);

/**
 * @brief 编码NODE_MOVE响应，OK回显原源ID与键，非OK为空body
 *
 * @param[in] value
 *     必需独立只读响应，sequence非零；OK要求非零handle/node/key，非OK三者全零。
 * @param[out] wire
 *     必需capacity字节独立可写区，失败整个容量保持。
 * @param[in] capacity
 *     真实容量，完整成功须容纳32或64字节。
 * @param[out] out_size
 *     必需独立地址，仅成功写实际完整长度，失败保持。
 *
 * @retval VIREO_OK
 *     CRC帧发布，flags仅RESPONSE、task为0；OK固定64字节，非OK固定32字节。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL或状态/成员关系非法，先于容量拒绝。
 * @retval VIREO_RESULT_RANGE
 *     宿主值合法而容量不足，输出保持。
 * @return codec/TLV依赖意外错误沿其rc，不发布部分帧。
 *
 * @note 允许19状态：OK/BAD_REQUEST/UNSUPPORTED/CRC_MISMATCH/BODY_TOO_LARGE/INVALID_FLAGS/
 *     DUPLICATE_REQUEST/RATE_LIMITED/UNAUTHORIZED/FORBIDDEN/NOT_FOUND/INVALID_PATH/CONFLICT/
 *     BUSY/INTERNAL_ERROR/DB_ERROR/TIMEOUT/OVERLOADED/UNAVAILABLE。
 *     OK只表达原逻辑操作曾成功，首次不变操作与历史恢复格式相同，不报告当前位置/changed。
 *     非OK不证明数据库未提交；不得按TIMEOUT/DB_ERROR/断连自动换键重新移动。
 * @note 地址有效对齐独立不重叠且不指向errno，短借至返回，不接管owner或保存指针。
 *     无分配/I/O/锁/采时/重试，保持errno；独立对象可并发，同输出外部同步。
 */
vireo_result_t vireo_node_move_response_encode(const vireo_node_move_response_t *value,
    unsigned char *wire, size_t capacity, size_t *out_size);

/**
 * @brief 校验恰好一个响应并复制独立值，不自动重试或查询当前节点
 *
 * @param[in] wire
 *     必需稳定只读wire_size字节，短借至返回，不保留视图。
 * @param[in] wire_size
 *     实际完整长度，成功只允许32或64，必须匹配header且无尾随字节。
 * @param[out] out
 *     必需独立独占输出，仅成功修改，失败原字节含padding保持；非OK时node/key为0。
 * @param[out] issue
 *     必需独立诊断；非NULL入口置NONE，格式拒绝写本地类别。
 *
 * @retval VIREO_OK
 *     response_encode的完整字节/成员关系通过；合法非OK业务响应亦返回OK。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL，非NULL issue仍重置。
 * @retval VIREO_RESULT_PROTOCOL
 *     长度/header/包络/CRC/TLV/取值关系错误，out保持。
 *
 * @note 先实际有界长度，再header/包络/CRC/字段/值；完整消费，允许两个OK字段乱序。
 *     caller仍核本次command/sequence、OK handle/原node_id/原键，不能从codec通过推断关联。
 *     错误handle0不改变绑定；历史OK不保证当前仍在原目标，需另发STAT/LIST观察。
 * @note 全部地址独立有效对齐不指向errno；无保存借用、分配/I/O/锁/采时/重试。
 *     保持errno，独立对象可并发，同输出须外部同步。
 */
vireo_result_t vireo_node_move_response_decode(const unsigned char *wire, size_t wire_size,
    vireo_node_move_response_t *out, vireo_node_move_issue_t *issue);
#endif
