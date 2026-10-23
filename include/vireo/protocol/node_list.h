/* PROJECT : VIREO; FILE : node_list.h; AUTHOR : bitofux; DATE : 2026-10-22;
 * BRIEF : NODE_LIST有界完整帧；token只复制字节，认证与授权归业务层。 */
#ifndef VIREO_PROTOCOL_NODE_LIST_H
#define VIREO_PROTOCOL_NODE_LIST_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <vireo/base/result.h>
#include <vireo/protocol/protocol.h>
#define VIREO_NODE_LIST_TLV_DIRECTORY_ID UINT16_C(0x0410)
#define VIREO_NODE_LIST_TLV_PAGE_SIZE UINT16_C(0x0411)
#define VIREO_NODE_LIST_TLV_PAGE_TOKEN UINT16_C(0x0412)
#define VIREO_NODE_LIST_TLV_NODE_ENTRY UINT16_C(0x0413)
#define VIREO_NODE_LIST_TLV_NEXT_PAGE_TOKEN UINT16_C(0x0414)
#define VIREO_NODE_LIST_TLV_NODE_ID UINT16_C(0x0401)
#define VIREO_NODE_LIST_TLV_PARENT_ID UINT16_C(0x0402)
#define VIREO_NODE_LIST_TLV_NAME_BYTES UINT16_C(0x0403)
#define VIREO_NODE_LIST_TLV_NODE_TYPE UINT16_C(0x0404)
#define VIREO_NODE_LIST_TLV_SIZE UINT16_C(0x0405)
#define VIREO_NODE_LIST_TLV_CREATED_AT_MS UINT16_C(0x0406)
#define VIREO_NODE_LIST_TLV_UPDATED_AT_MS UINT16_C(0x0407)
#define VIREO_NODE_LIST_TLV_OBJECT_HASH UINT16_C(0x0408)
#define VIREO_NODE_LIST_PAGE_CAPACITY ((size_t)64)
#define VIREO_NODE_LIST_NAME_CAPACITY ((size_t)255)
#define VIREO_NODE_LIST_TOKEN_SIZE ((size_t)96)
#define VIREO_NODE_LIST_REQUEST_BODY_MIN ((size_t)18)
#define VIREO_NODE_LIST_REQUEST_BODY_MAX ((size_t)118)
#define VIREO_NODE_LIST_REQUEST_FRAME_MIN ((size_t)50)
#define VIREO_NODE_LIST_REQUEST_FRAME_MAX ((size_t)150)
#define VIREO_NODE_LIST_ENTRY_BODY_MAX ((size_t)361)
#define VIREO_NODE_LIST_RESPONSE_BODY_MAX ((size_t)23478)
#define VIREO_NODE_LIST_RESPONSE_FRAME_MAX ((size_t)23510)
typedef uint16_t vireo_node_list_type_t;
#define VIREO_NODE_LIST_DIRECTORY UINT16_C(1)
#define VIREO_NODE_LIST_FILE UINT16_C(2)
/** @brief 独立请求；显式目录/页大小，无当前目录、默认页大小或裸after_id。 */
typedef struct vireo_node_list_request {
    uint32_t sequence; /**< 非零，每页新sequence。 */
    uint32_t session_handle; /**< 原短句柄，0允许解析但须另做认证。 */
    uint64_t directory_id; /**< 非零目标目录，不证明授权。 */
    uint16_t page_size; /**< 1..64。 */
    bool has_page_token; /**< false为第一页，数组须全零；true恰好96字节。 */
    unsigned char page_token[VIREO_NODE_LIST_TOKEN_SIZE]; /**< 独立复制，codec不解释MAC或上下文。 */
} vireo_node_list_request_t;
/** @brief 仅LIST拥有的子节点元数据；每项都必须有父，非wire或数据库ABI。 */
typedef struct vireo_node_list_entry {
    uint64_t node_id; /**< 非零，非目录本身，页内严格升序。 */
    uint64_t parent_id; /**< 等于response.directory_id。 */
    unsigned char name[VIREO_NODE_LIST_NAME_CAPACITY]; /**< 原始名字，无NUL/斜杠，非单点双点。 */
    size_t name_length; /**< 1..255；不保证UTF8或NUL结束。 */
    vireo_node_list_type_t type; /**< 目录1/文件2。 */
    uint64_t size; /**< 目录0，文件任意u64。 */
    uint64_t created_at_ms; /**< UTC毫秒，0合法。 */
    uint64_t updated_at_ms; /**< >=created。 */
    bool has_object_hash; /**< 文件true，目录false。 */
    unsigned char object_hash[32]; /**< 文件BLAKE3元数据；目录全零，不证明CAS。 */
} vireo_node_list_entry_t;
/** @brief 独立一页；count由ENTRY次数推导，has_more映射MORE和NEXT存在性。 */
typedef struct vireo_node_list_response {
    vireo_status_t status; /**< 本头列明15状态；非OK其余业务成员全零。 */
    uint32_t sequence; /**< 原非零sequence。 */
    uint32_t session_handle; /**< OK非零回显；错误0，不是logout指令。 */
    uint64_t directory_id; /**< OK非零，caller核对原目录。 */
    uint16_t page_size; /**< OK原请求1..64。 */
    size_t count; /**< <=page_size；MORE时等于page_size。 */
    bool has_more; /**< true恰有NEXT；false则token全零。 */
    unsigned char next_page_token[VIREO_NODE_LIST_TOKEN_SIZE]; /**< 固定独立复制；不证明授权。 */
    vireo_node_list_entry_t entries[VIREO_NODE_LIST_PAGE_CAPACITY]; /**< 有效前缀；decode未用槽归零。 */
} vireo_node_list_response_t;
/** @brief 去敏本地诊断，非业务或密码学结果。 */
typedef enum vireo_node_list_issue {
    VIREO_NODE_LIST_ISSUE_NONE = 0,
    VIREO_NODE_LIST_ISSUE_HEADER = 1,
    VIREO_NODE_LIST_ISSUE_ENVELOPE = 2,
    VIREO_NODE_LIST_ISSUE_CRC = 3,
    VIREO_NODE_LIST_ISSUE_FIELDS = 4,
    VIREO_NODE_LIST_ISSUE_VALUE = 5
} vireo_node_list_issue_t;
/** @brief 编码一帧NODE_LIST请求，50或150字节。
 * @param[in] value 必需独立只读请求，满足字段合同，只借至返回。
 * @param[out] wire 必需真实capacity字节可写区，失败整区保持。
 * @param[in] capacity 真实容量；合法值但不足完整帧为RANGE。
 * @param[out] out_size 必需独立地址，仅成功写完整帧长度。
 * @retval VIREO_OK 完整帧已发布，flags/status/task为0。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL或宿主值非法。
 * @retval VIREO_RESULT_RANGE 容量不足，wire/out_size保持。
 * @return 依赖意外错误沿原rc，输出保持。
 * @note 地址有效对齐、互不重叠且不指向errno；不保存借用或接管owner。
 * 无分配/I/O/锁/采时/重试，保持errno；独立对象并发，同输出外部同步。 */
vireo_result_t vireo_node_list_request_encode(const vireo_node_list_request_t *value,
    unsigned char *wire, size_t capacity, size_t *out_size);
/** @brief 精确校验完整请求并一次发布独立值，不做token认证。
 * @param[in] wire 必需稳定只读wire_size字节，借至返回。
 * @param[in] wire_size 实际长度；不接受尾随帧，0长度允许报告PROTOCOL。
 * @param[out] out 必需独立对象；失败包含padding保持，成功复制token。
 * @param[out] issue 必需独立诊断；非NULL入口置NONE。
 * @retval VIREO_OK 仅格式/schema正确，未验证身份、MAC或目录权限。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL，非NULL issue仍重置。
 * @retval VIREO_RESULT_PROTOCOL 字节/字段/值非法，out保持。
 * @note 地址有效对齐、互不重叠且不指向errno；无分配/I/O/锁/采时/重试。
 * 保持errno，不保存地址；独立对象可并发，同输出外部同步。 */
vireo_result_t vireo_node_list_request_decode(const unsigned char *wire, size_t wire_size,
    vireo_node_list_request_t *out, vireo_node_list_issue_t *issue);
/** @brief 编码一帧列表响应；错误32字节，OK50..23510字节。
 * @param[in] value 必需只读独立响应，满足下述状态/元数据/顺序/MORE合同。
 * @param[out] wire 必需capacity真实可写区，失败整区保持。
 * @param[in] capacity 真实容量；不够本次帧为RANGE。
 * @param[out] out_size 必需独立地址，仅成功改实际帧长。
 * @retval VIREO_OK 完整发布，flags为RESPONSE或RESPONSE|MORE，task0。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL或非法宿主成员；错误成员须清零。
 * @retval VIREO_RESULT_RANGE 合法值但空间不足，wire/out_size保持。
 * @return 依赖意外错误沿原rc，输出保持。
 * @note 无分配/I/O/锁/采时/重试，保持errno。输入借至返回，无owner转移。
 * 地址有效对齐互不重叠不指向errno；独立对象可并发，同输出外部同步。
 * 允许OK、BAD_REQUEST、UNSUPPORTED、CRC_MISMATCH、BODY_TOO_LARGE、INVALID_FLAGS、
 * DUPLICATE_REQUEST、RATE_LIMITED、UNAUTHORIZED、NOT_FOUND、BUSY、INTERNAL_ERROR、
 * TIMEOUT、OVERLOADED、UNAVAILABLE；不解析/签发token，不证明授权或CAS可用。
 * OK要求directory非零，page_size1..64，count<=page_size；MORE时count==page_size。
 * 有效entry的ID非零、非目录本身且严格递增，parent等于directory。
 * 名字1..255字节且禁止NUL/斜杠/单点/双点；updated>=created，时间0合法。
 * 目录size0/无hash/数组全零；文件有32字节hash，size任意u64。
 * 无MORE则token数组全零；非OK全部业务成员含64个entry归零，不检查padding。
 * OK编码忽略未用entry槽及名字尾部，decode将其归零；单值字段未知/重复/缺项拒绝。
 * 外层ENTRY可重复；编码type升序，解码允许字段乱序但ENTRY遇见次序须ID递增。 */
vireo_result_t vireo_node_list_response_encode(const vireo_node_list_response_t *value,
    unsigned char *wire, size_t capacity, size_t *out_size);
/** @brief 精确校验一帧响应并独立复制整页，非OK也可解析成功。
 * @param[in] wire 必需稳定只读实际wire_size字节，借至返回。
 * @param[in] wire_size 实际完整长度32..23510；尾随数据拒绝。
 * @param[out] out 必需独立对象，仅完整成功改动，失败含padding保持。
 * @param[out] issue 必需独立诊断，非NULL入口置NONE。
 * @retval VIREO_OK 满足response_encode字节合同，业务status由caller处理。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL，非NULL issue仍重置。
 * @retval VIREO_RESULT_PROTOCOL header/CRC/TLV/值或关系不合法，out保持。
 * @note 未用entry/名字尾部/token归零；caller核在途sequence/handle/目录/page_size。
 * 无认证/分配/I/O/锁/采时/重试，保持errno，不保存借用或接管owner。
 * 地址有效对齐互不重叠不指向errno；独立对象可并发，同输出外部同步。 */
vireo_result_t vireo_node_list_response_decode(const unsigned char *wire, size_t wire_size,
    vireo_node_list_response_t *out, vireo_node_list_issue_t *issue);
#endif
