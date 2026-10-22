/* PROJECT : VIREO; FILE : node_stat.h;
 * AUTHOR : bitofux; DATE : 2026-10-22;
 * BRIEF : NODE_STAT完整请求/响应帧；只依赖协议，不依赖service/数据库。 */
#ifndef VIREO_PROTOCOL_NODE_STAT_H
#define VIREO_PROTOCOL_NODE_STAT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <vireo/base/result.h>
#include <vireo/protocol/protocol.h>

/* 仅NODE_STAT请求/响应body采用以下字段；不修改旧auth的局部编号。 */
#define VIREO_NODE_STAT_TLV_NODE_ID UINT16_C(0x0401)
#define VIREO_NODE_STAT_TLV_PARENT_ID UINT16_C(0x0402)
#define VIREO_NODE_STAT_TLV_NAME_BYTES UINT16_C(0x0403)
#define VIREO_NODE_STAT_TLV_NODE_TYPE UINT16_C(0x0404)
#define VIREO_NODE_STAT_TLV_SIZE UINT16_C(0x0405)
#define VIREO_NODE_STAT_TLV_CREATED_AT_MS UINT16_C(0x0406)
#define VIREO_NODE_STAT_TLV_UPDATED_AT_MS UINT16_C(0x0407)
#define VIREO_NODE_STAT_TLV_OBJECT_HASH UINT16_C(0x0408)
#define VIREO_NODE_STAT_NAME_CAPACITY ((size_t)255)
#define VIREO_NODE_STAT_REQUEST_BODY_SIZE ((size_t)12)
#define VIREO_NODE_STAT_REQUEST_FRAME_SIZE ((size_t)44)
#define VIREO_NODE_STAT_RESPONSE_BODY_MAX ((size_t)361)
#define VIREO_NODE_STAT_RESPONSE_FRAME_MAX ((size_t)393)

/** @brief 固定wire u16类型值；与持久enum分别定义，不依赖数据库头。 */
typedef uint16_t vireo_node_stat_type_t;
#define VIREO_NODE_STAT_DIRECTORY UINT16_C(1)
#define VIREO_NODE_STAT_FILE UINT16_C(2)

/** @brief 完整校验后发布的独立请求值；没有指向输入帧的借用。 */
typedef struct vireo_node_stat_request {
    uint32_t sequence; /**< 必需非零，仅请求关联，不是权限票据。 */
    uint32_t session_handle; /**< 原帧短句柄；0合法表示未绑定，Reactor另核身份并拒绝未认证。 */
    uint64_t node_id; /**< 必需非零；根须真实ID，0无隐含语义。 */
} vireo_node_stat_request_t;

/** @brief 仅协议拥有的独立元数据；不是MySQL DTO、文件系统stat或wire布局。 */
typedef struct vireo_node_stat_metadata {
    uint64_t node_id; /**< 非零公开资源选择器，不证明授权；无owner_id字段。 */
    bool has_parent; /**< 对应PARENT_ID是否存在；根false，其余true。 */
    uint64_t parent_id; /**< has_parent时非零，否则0；不证明祖先可达或无环。 */
    unsigned char name[VIREO_NODE_STAT_NAME_CAPACITY]; /**< NAME_BYTES原样副本，不保证UTF8或NUL。 */
    size_t name_length; /**< 根0、非根1..255；未用数组尾部不编码，decode归零。 */
    vireo_node_stat_type_t type; /**< 目录1或文件2，以u16大端编码。 */
    uint64_t size; /**< 目录0，文件允许0..UINT64_MAX。 */
    uint64_t created_at_ms; /**< UTC epoch毫秒，0合法，不采本机时钟。 */
    uint64_t updated_at_ms; /**< 不小于created。 */
    bool has_object_hash; /**< 文件必须true、目录必须false；对应HASH字段存在性。 */
    unsigned char object_hash[32]; /**< 声明的BLAKE3-256元数据，所有位模式合法；目录全零；不证明CAS存在。 */
} vireo_node_stat_metadata_t;

/** @brief 独立响应值；command固定NODE_STAT，不在结构体里冗余。 */
typedef struct vireo_node_stat_response {
    vireo_status_t status; /**< response_encode合同列明的15个状态之一；禁止内部rc强转。 */
    uint32_t sequence; /**< 必需原请求非零序号，关联检查仍归caller。 */
    uint32_t session_handle; /**< OK回显原请求非零句柄；非OK为0，不改变客户端绑定。 */
    vireo_node_stat_metadata_t metadata; /**< 仅OK有效；非OK全部成员归零，不检查padding。 */
} vireo_node_stat_response_t;

/** @brief 去敏本地诊断，不是wire状态，不含名字/SQL/输入片段。 */
typedef enum vireo_node_stat_issue {
    VIREO_NODE_STAT_ISSUE_NONE = 0,
    VIREO_NODE_STAT_ISSUE_HEADER = 1, /**< 公共framing/方向基础规则失败。 */
    VIREO_NODE_STAT_ISSUE_ENVELOPE = 2, /**< command/精确flags/handle/有界帧长/状态集合失败。 */
    VIREO_NODE_STAT_ISSUE_CRC = 3, /**< 当前精确帧CRC不一致。 */
    VIREO_NODE_STAT_ISSUE_FIELDS = 4, /**< TLV完整性、未知、重复、缺项或字段长度错误。 */
    VIREO_NODE_STAT_ISSUE_VALUE = 5 /**< 零ID、类型、名字或节点字段关联不满足合同。 */
} vireo_node_stat_issue_t;

/**
 * @brief 编码NODE_STAT完整请求帧，固定44字节且只有一个NODE_ID TLV
 * @param[in] value 必需只读独立请求，sequence/node_id非零，handle允许0。
 * @param[out] wire 必需capacity字节可写区，不与value/out_size重叠，失败整区保持。
 * @param[in] capacity 真实容量，可小于44；不是允许写入的虚构长度。
 * @param[out] out_size 必需独立地址，成功写44，失败保持。
 * @retval VIREO_OK 完整帧已发布，flags/status/task_handle为0、CRC正确。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需地址NULL或宿主值非法。
 * @retval VIREO_RESULT_RANGE 值合法但容量不足。
 * @return 内部codec/TLV依赖意外失败沿其rc，输出保持。
 * @note 无分配/I/O/阻塞/重试，保持errno；独立对象可并发，同输出须外部同步。
 *     所有地址有效对齐不重叠且不指向errno，输入借至返回，不保存地址或接管owner。
 */
vireo_result_t vireo_node_stat_request_encode(const vireo_node_stat_request_t *value,
    unsigned char *wire, size_t capacity, size_t *out_size);

/**
 * @brief 校验恰好一帧NODE_STAT请求并发布独立值，不验证身份或数据库权限
 * @param[in] wire 必需稳定只读wire_size字节，不保存借用，长度0允许传入以报告PROTOCOL。
 * @param[in] wire_size 实际完整帧字节数；必须恰好44，不接受后续帧/尾随字节。
 * @param[out] out 必需独立对象，仅成功修改；失败保留原对象含padding。
 * @param[out] issue 必需独立诊断，非NULL时入口置NONE，协议拒绝写相应类别。
 * @retval VIREO_OK 请求有界、header/CRC/TLV/非零节点通过，handle=0亦可成功解析。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需地址NULL；非NULL issue仍重置。
 * @retval VIREO_RESULT_PROTOCOL 字节、schema或取值错误，out保持。
 * @note 全部地址独立有效不重叠且不指向errno；无分配/I/O/锁/认证，保持errno。
 *     先检查有界帧长，再处理body；完整消费，未知/重复/缺失字段拒绝。
 *     输入只借至返回，结果无指针；独立对象可并发，同输出须外部同步。
 */
vireo_result_t vireo_node_stat_request_decode(const unsigned char *wire, size_t wire_size,
    vireo_node_stat_request_t *out, vireo_node_stat_issue_t *issue);

/**
 * @brief 编码完整NODE_STAT响应；非OK为空body，OK显式编码元数据
 * @param[in] value 必需独立只读响应，满足下述状态及节点关系，借至返回。
 * @param[out] wire 必需capacity字节独立可写区，失败整区保持，不直接发送C布局。
 * @param[in] capacity 真实容量，成功帧32..393字节，必须容纳本次完整帧。
 * @param[out] out_size 必需独立地址，仅成功写实际帧长。
 * @retval VIREO_OK 完整帧已发布，flags仅RESPONSE、task_handle=0、CRC正确。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需地址NULL或宿主值/状态/节点关系非法。
 * @retval VIREO_RESULT_RANGE 值合法但本次完整帧放不下，wire/out_size保持。
 * @return 内部codec/TLV依赖意外失败沿其rc，输出保持。
 * @note 允许状态：OK、BAD_REQUEST、UNSUPPORTED、CRC_MISMATCH、BODY_TOO_LARGE、
 *     INVALID_FLAGS、DUPLICATE_REQUEST、RATE_LIMITED、UNAUTHORIZED、NOT_FOUND、
 *     BUSY、INTERNAL_ERROR、TIMEOUT、OVERLOADED、UNAVAILABLE；非OK metadata各成员为0。
 * @note 根：无PARENT、name长度0、目录、size0、无HASH；非根PARENT非零、name1..255。
 *     NAME_BYTES不含NUL/斜杠且非单点/双点；其余字节保留，不作UTF8或规范化验证。
 *     文件有且仅一个32字节HASH，目录无HASH且数组为0；updated>=created。
 *     所有单值字段唯一；编码按type升序，解码允许任意顺序。
 * @note 地址有效对齐不重叠且不指向errno；不保存、接管或销毁外部资源。
 *     无分配/I/O/锁/采时/重试，保持errno；独立对象可并发，同输出须外部同步。
 */
vireo_result_t vireo_node_stat_response_encode(const vireo_node_stat_response_t *value,
    unsigned char *wire, size_t capacity, size_t *out_size);

/**
 * @brief 校验恰好一帧响应并发布独立值；不自动匹配在途请求或证明授权
 * @param[in] wire 必需稳定只读wire_size字节，只借至返回。
 * @param[in] wire_size 实际完整帧长，32..393，精确匹配header声明，不接受尾随字节。
 * @param[out] out 必需独立对象，仅成功修改；名字/hash已复制，未用数组尾部归零。
 * @param[out] issue 必需独立诊断，非NULL时入口置NONE，拒绝时为本地类别。
 * @retval VIREO_OK 满足response_encode所有wire/字段规则，非OK为合法业务响应。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需地址NULL，非NULL issue仍重置。
 * @retval VIREO_RESULT_PROTOCOL header/有界长/CRC/TLV/取值或字段关系非法，out保持含padding。
 * @note 地址有效不重叠、不指向errno，无分配/I/O/锁/认证，保持errno，独立对象可并发。
 *     成功只证明字节/schema合法；caller仍核command所对应在途请求、sequence、
 *     OK句柄与node_id关联。非OK的handle0不是logout指令，不修改Session绑定。
 *     metadata不含owner/持久Session/仓库报告，hash不证明CAS，name须按字节安全展示。
 */
vireo_result_t vireo_node_stat_response_decode(const unsigned char *wire, size_t wire_size,
    vireo_node_stat_response_t *out, vireo_node_stat_issue_t *issue);
#endif
