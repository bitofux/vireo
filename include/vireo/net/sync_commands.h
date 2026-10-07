/*
- PROJECT : VIREO
- FILE    : sync_commands.h
- AUTHOR  : bitofux
- DATE    : 2026-10-07
- BRIEF   : 此模块负责：
- -- PING空响应与缓存型SERVER_INFO的固定schema
- -- 复用tcp_server同步handler与调用者固定context
 */
#ifndef VIREO_NET_SYNC_COMMANDS_H
#define VIREO_NET_SYNC_COMMANDS_H

#include <vireo/net/tcp_server.h>

/* 仅分配这三个诊断字段号，其他业务 TLV 编号尚未定义。 */
/** 必需单值TLV：两字节大端协议版本，当前值1。 */
#define VIREO_SYNC_TLV_PROTOCOL_VERSION UINT16_C(0xF001)
/** 必需单值TLV：1..64个ASCII 0x21..0x7E版本字节，无NUL。 */
#define VIREO_SYNC_TLV_SERVER_VERSION UINT16_C(0xF002)
/** 必需单值TLV：PING与SERVER_INFO两个大端u16，共4字节。 */
#define VIREO_SYNC_TLV_SUPPORTED_COMMANDS UINT16_C(0xF003)
/** 应用版本有效字节硬限，不包含字符串终止符。 */
#define VIREO_SYNC_MAX_VERSION_BYTES ((size_t)64)
/** 三个诊断TLV的body容量硬限；实际长度为18加版本长度，不含32字节头。 */
#define VIREO_SYNC_MAX_INFO_BODY_BYTES ((size_t)82)

/**
 * @brief 应用拥有的固定 SERVER_INFO 快照，不是 wire 结构体
 *
 * 必须用 sync_context_init 初始化。字段只供观察，初始化后不得直接修改。
 * 版本已复制；可按值复制到独立存储。无资源 owner、fd 或外部指针。
 */
typedef struct vireo_tcp_server_sync_context {
    uint8_t server_info_body[VIREO_SYNC_MAX_INFO_BODY_BYTES]; /**< 只前缀是完整 TLV body。 */
    size_t server_info_body_size; /**< 有效字节数 19..82，整帧为此值加 32。 */
} vireo_tcp_server_sync_context_t;

/**
 * @brief 在局部完整编码版本快照，成功后整体发布固定缓存
 *
 * @param[in] version
 *     非空独立版本字节，只借用至返回；每字节为 ASCII 0x21..0x7E。
 * @param[in] version_size
 *     正 1..64，不含 NUL 终止符，不解析 semver，不读取字符串尾部。
 * @param[out] out_context
 *     必需独立可写对象，失败保持全部字节；不得在借用在途时重新初始化。
 *
 * @retval VIREO_OK
 *     发布三个完整单值 TLV：协议版本 u16=1、版本字节、两个大端 u16 命令 ID。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空、长度为零或字符不符，输出保持。
 * @retval VIREO_RESULT_RANGE
 *     长度超过 64，输出保持。
 * @retval VIREO_RESULT_OVERFLOW
 *     长度计算不可表示，输出保持；依赖其他错误原样返回。
 *
 * @note body 长度为 18+version_size；仅分配三个诊断 type，其他业务 schema 未冻结。
 *     字段必需、单值，编码顺序为协议版本、软件版本、支持命令；整数大端。
 * @note 没有 heap、锁、系统调用或资源转移。应用负责版本内容真实，存储与版本独立。
 *     初始化与任何读者不得并发；所有路径恢复入口 errno。
 */
vireo_result_t vireo_tcp_server_sync_context_init(uint8_t const *version, size_t version_size,
                                                  vireo_tcp_server_sync_context_t *out_context);

/**
 * @brief 在给定 body 工作区生成 PING / SERVER_INFO 的 SINGLE 响应描述
 *
 * @param[in] request
 *     必需、已通过原 REQUEST framing/长度/完整性/CRC 的只读帧，只借用至返回。
 * @param[out] body
 *     独立固定工作区；容量正时必需非空，零时可 NULL 或不可解引用尾后地址。
 * @param[in] body_capacity
 *     真实可写字节数；INFO 至少为 cache 实际长度，不要求总是 82。
 * @param[in,out] reply
 *     必需独立描述，失败保持；成功整体写 status/body_size/零 session 与 task。
 * @param[in] context
 *     必需正确初始化、未被篡改的 sync_context。整个 process/drive/run 借用期间只读有效。
 *
 * @retval VIREO_OK
 *     业务响应已生成：PING 为 OK 空 body，INFO 为 OK 缓存，业务拒绝为空 body。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空、缓存长度异常或帧视图成员不一致，主要输出保持。
 * @retval VIREO_RESULT_RANGE
 *     INFO 工作区不足，主要输出保持，不截断、不回协议错误、不自动重试。
 * @retval VIREO_RESULT_OVERFLOW
 *     视图整帧长度不可表示，主要输出保持。
 * @retval VIREO_RESULT_PROTOCOL
 *     防御性基础 header 验证失败，主要输出保持；不重新验证原 wire/CRC。
 *
 * @note 两诊断请求依次检查 flags==0、两个 handles==0、body 为空；拒绝分别为
 *     INVALID_FLAGS、BAD_REQUEST。其他已登记命令为 UNSUPPORTED；未知命令在原 framing
 *     就已 PROTOCOL 拒绝，本函数不能使其成为合法响应。不分配错误消息或记录 body。
 * @note 成功只写实际 body 前缀，未写尾部保持。command/sequence/RESPONSE/header/CRC
 *     由原 server 编码；它先完整 enqueue 再 consume。handler 非 OK 时本帧不消费，
 *     此前进度沿旧合同保留。业务拒绝 OK+status 与本地 result 分开，不自动关闭/归还。
 * @note 不保留 request/body/reply，不改变 cache 或 server，不执行 I/O/heap/收发/关注修改。
 *     所有存储独立有效、对齐且不重叠；缓存长度检查不能认证伪造或被篡改的对象。
 * @note Reactor 有界回调，原在途保护保持；独立输出可共享真正不可变 cache，读者期间
 *     不释放/重初始化。所有路径恢复入口 errno，参数签名匹配原 sync_handler_t。
 */
vireo_result_t vireo_tcp_server_handle_sync_command(vireo_connection_frame_view_t const *request,
                                                    uint8_t *body, size_t body_capacity,
                                                    vireo_tcp_server_reply_t *reply, void *context);

#endif /* VIREO_NET_SYNC_COMMANDS_H */
